/* Final kernel offsets header for iPad8,9 iOS 17.3.1 (21D61)
 * - Combines verified sandbox function offsets and AMFI cs_enforcement_disable (if found).
 * - cs_enforcement_disable was not located statically in the AMFI kext; placeholder included.
 */

#ifndef FINAL_KERNEL_OFFSETS_H
#define FINAL_KERNEL_OFFSETS_H

#include "offsets_sandbox_candidates.h"
#include "sandbox_verified_offsets.h"

/* cs_enforcement_disable function signature discovered via ADRP+ADD XREF scan */
static const unsigned char cs_enforcement_sig[] = {
    0xFD,0x7B,0x0F,0xA9,0xFD,0xC3,0x03,0x91,0x68,0x5F,0xFF,0x90,0x08,0xE5,0x44,0xF9,
    0x08,0x01,0x40,0xF9,0xA8,0x83,0x1C,0xF8,0xAF,0x6F,0xD0,0x97,0xF3,0x03,0x00,0xAA
};
#define CS_ENFORCEMENT_SIG_LEN 32

typedef struct {
    uint64_t addr; /* absolute virtual address */
    uint64_t offset_from_kernel; /* KERNEL_BASE + offset */
    const unsigned char *sig; /* first 32 bytes signature */
    size_t siglen;
    const char *name;
    const char *confidence; /* High / Medium / Low / NotFound */
} final_offset_t;

static final_offset_t final_kernel_offsets[] = {
    /* Sandbox functions (from sandbox_verified_offsets.h) */
    { KERNEL_BASE + 0x02DFE3A8ULL, 0x02DFE3A8ULL, sandbox_sig_1, SANDBOX_SIG_1_LEN, "sandbox_check", "High" },
    { KERNEL_BASE + 0x02E02388ULL, 0x02E02388ULL, sandbox_sig_5, SANDBOX_SIG_5_LEN, "mac_label_update", "High" },
    { KERNEL_BASE + 0x02E26A0CULL, 0x02E26A0CULL, sandbox_sig_12, SANDBOX_SIG_12_LEN, "sandbox_extension_create_or_consume", "High" },
    /* AMFI: cs_enforcement_disable function (discovered statically via ADRP+ADD XREF) */
    { 0xFFFFFFF008F2F764ULL, 0x01F2B764ULL, cs_enforcement_sig, CS_ENFORCEMENT_SIG_LEN, "cs_enforcement_disable", "High" },
};

#define FINAL_KERNEL_OFFSETS_COUNT (sizeof(final_kernel_offsets)/sizeof(final_kernel_offsets[0]))

#pragma mark -- convenience struct for sandbox_patches.m

typedef struct {
    uint64_t sandbox_check_addr;
    const unsigned char *sandbox_check_sig;
    size_t sandbox_check_siglen;
    uint64_t mac_label_update_addr;
    const unsigned char *mac_label_update_sig;
    size_t mac_label_update_siglen;
    uint64_t sandbox_extension_addr;
    const unsigned char *sandbox_extension_sig;
    size_t sandbox_extension_siglen;
    uint64_t cs_enforcement_disable_addr;
    const unsigned char *cs_enforcement_disable_sig;
    size_t cs_enforcement_disable_siglen;
} sandbox_offsets_t;

static const sandbox_offsets_t sandbox_offsets = {
    /* addresses are absolute virtual addresses */
    KERNEL_BASE + 0x02DFE3A8ULL,
    sandbox_sig_1,
    SANDBOX_SIG_1_LEN,
    KERNEL_BASE + 0x02E02388ULL,
    sandbox_sig_5,
    SANDBOX_SIG_5_LEN,
    KERNEL_BASE + 0x02E26A0CULL,
    sandbox_sig_12,
    SANDBOX_SIG_12_LEN,
    0xFFFFFFF008F2F764ULL,
    cs_enforcement_sig,
    CS_ENFORCEMENT_SIG_LEN
};

#endif // FINAL_KERNEL_OFFSETS_H
