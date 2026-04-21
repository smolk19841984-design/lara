/* Verified sandbox offsets and signatures for iPad8,9 iOS 17.3.1 (21D61)
 * - Use as a starting point for runtime verification (kread) before patching.
 * - KERNEL_BASE taken from offsets_generated_iPad8_9_17_3_1.json
 */

#ifndef SANDBOX_VERIFIED_OFFSETS_H
#define SANDBOX_VERIFIED_OFFSETS_H

#include "offsets_sandbox_candidates.h"

#define KERNEL_BASE 0xFFFFFFF007004000ULL

typedef struct {
    uint64_t addr; /* absolute virtual address */
    uint64_t offset_from_kernel; /* KERNEL_BASE + offset */
    const unsigned char *sig; /* first 32 bytes signature */
    size_t siglen;
    const char *name;
    const char *confidence; /* High / Medium / Low */
} sandbox_verified_t;

static sandbox_verified_t sandbox_verified[] = {
    { KERNEL_BASE + 0x02DFE3A8ULL, 0x02DFE3A8ULL, sandbox_sig_1, SANDBOX_SIG_1_LEN, "sandbox_check", "Medium" },
    { KERNEL_BASE + 0x02E02388ULL, 0x02E02388ULL, sandbox_sig_5, SANDBOX_SIG_5_LEN, "mac_label_update", "High" },
    { KERNEL_BASE + 0x02E26A0CULL, 0x02E26A0CULL, sandbox_sig_12, SANDBOX_SIG_12_LEN, "sandbox_extension_create_or_consume", "High" },
};

#define SANDBOX_VERIFIED_COUNT (sizeof(sandbox_verified)/sizeof(sandbox_verified[0]))

#endif // SANDBOX_VERIFIED_OFFSETS_H
