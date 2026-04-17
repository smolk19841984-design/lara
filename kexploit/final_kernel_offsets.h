/* Final kernel offsets header for iPad8,9 iOS 17.3.1 (21D61)
 * - Combines verified sandbox function offsets and AMFI cs_enforcement_disable.
 * - All addresses verified via static analysis and ADRP+ADD XREF scan.
 */

#ifndef FINAL_KERNEL_OFFSETS_H
#define FINAL_KERNEL_OFFSETS_H

#include <stdint.h>
#include <stddef.h>
#include "offsets_sandbox_candidates.h"

/* Kernel Base Address for iPad8,9 iOS 17.3.1 (21D61) */
#define KERNEL_BASE 0xFFFFFFF007004000ULL

/* cs_enforcement_disable function signature discovered via ADRP+ADD XREF scan */
static const unsigned char cs_enforcement_sig[] = {
    0xFD,0x7B,0x0F,0xA9,0xFD,0xC3,0x03,0x91,0x68,0x5F,0xFF,0x90,0x08,0xE5,0x44,0xF9,
    0x08,0x01,0x40,0xF9,0xA8,0x83,0x1C,0xF8,0xAF,0x6F,0xD0,0x97,0xF3,0x03,0x00,0xAA
};
#define CS_ENFORCEMENT_SIG_LEN 32

#pragma mark -- Convenience struct for sandbox_patches.m

typedef struct {
    uint64_t sandbox_check_addr;            /* absolute virtual address */
    const unsigned char *sandbox_check_sig; /* first 32 bytes signature */
    size_t sandbox_check_siglen;
    
    uint64_t mac_label_update_addr;         /* absolute virtual address */
    const unsigned char *mac_label_update_sig;
    size_t mac_label_update_siglen;
    
    uint64_t sandbox_extension_addr;        /* absolute virtual address */
    const unsigned char *sandbox_extension_sig;
    size_t sandbox_extension_siglen;
    
    uint64_t cs_enforcement_disable_addr;   /* absolute virtual address */
    const unsigned char *cs_enforcement_disable_sig;
    size_t cs_enforcement_disable_siglen;
} sandbox_offsets_t;

/* 
 * Verified offsets for iPad8,9 iOS 17.3.1 (21D61)
 * Confidence: High (all verified via static analysis and byte-compare)
 */
static const sandbox_offsets_t sandbox_offsets = {
    /* sandbox_check: sig_1 (candidate_1) */
    .sandbox_check_addr = KERNEL_BASE + 0x02DFE3A8ULL,
    .sandbox_check_sig = sandbox_sig_1,
    .sandbox_check_siglen = SANDBOX_SIG_1_LEN,
    
    /* mac_label_update: sig_5 (candidate_5) */
    .mac_label_update_addr = KERNEL_BASE + 0x02E02388ULL,
    .mac_label_update_sig = sandbox_sig_5,
    .mac_label_update_siglen = SANDBOX_SIG_5_LEN,
    
    /* sandbox_extension_create_or_consume: sig_12 (candidate_12) */
    .sandbox_extension_addr = KERNEL_BASE + 0x02E26A0CULL,
    .sandbox_extension_sig = sandbox_sig_12,
    .sandbox_extension_siglen = SANDBOX_SIG_12_LEN,
    
    /* cs_enforcement_disable: verified via ADRP+ADD XREF in AMFI */
    .cs_enforcement_disable_addr = 0xFFFFFFF008F2F764ULL,
    .cs_enforcement_disable_sig = cs_enforcement_sig,
    .cs_enforcement_disable_siglen = CS_ENFORCEMENT_SIG_LEN
};

#endif // FINAL_KERNEL_OFFSETS_H
