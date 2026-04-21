/* runtime_offsets_fallback.h
 * Fallback offsets for iPad8,9 iOS 17.3.1 (generated from local workspace data).
 * Where exact 17.3.1 public offsets are unavailable, entries are marked UNVERIFIED_CLOSEST_MATCH
 * or MISSING. Use the runtime verification snippet below to confirm/fix values at runtime using
 * your `kread64(addr)` / `kread(addr, buf, len)` primitives.
 */
#ifndef RUNTIME_OFFSETS_FALLBACK_H
#define RUNTIME_OFFSETS_FALLBACK_H

// AMFI base (parsed from workspace static analysis) - VERIFIED
#define FALLBACK_AMFI_VM 0xfffffff007c86ae0ULL
#define FALLBACK_AMFI_FILEOFF 0x0c82ae0
#define FALLBACK_AMFI_STATUS_HIGH 3

// cs_enforcement_disable offset within AMFI struct: NOT resolved statically
// Please run runtime verification (see snippet) to discover the true offset.
#define FALLBACK_AMFI_CS_ENFORCEMENT_DISABLE_OFFSET 0x0 /* UNVERIFIED/MISSING - runtime check required */
#define FALLBACK_AMFI_CS_ENFORCEMENT_DISABLE_STATUS 1 /* 1=MISSING,2=MEDIUM,3=HIGH */

// VFS functions: no exact static matches in available public DBs/workspace
// Set to 0 and mark UNVERIFIED; use runtime verifier to locate.
#define FALLBACK_VN_OPEN_VM 0x0ULL
#define FALLBACK_VN_OPEN_STATUS 1

#define FALLBACK_VN_WRITE_VM 0x0ULL
#define FALLBACK_VN_WRITE_STATUS 1

#define FALLBACK_VN_CLOSE_VM 0x0ULL
#define FALLBACK_VN_CLOSE_STATUS 1

#define FALLBACK_VFS_CONTEXT_CURRENT_VM 0x0ULL
#define FALLBACK_VFS_CONTEXT_CURRENT_STATUS 1

#define FALLBACK_VNODE_PUT_VM 0x0ULL
#define FALLBACK_VNODE_PUT_STATUS 1

// TrustCache / kern_trustcache: not found in local public DBs
#define FALLBACK_KERN_TRUSTCACHE_VM 0x0ULL
#define FALLBACK_KERN_TRUSTCACHE_STATUS 1

/* Status codes
 * 3 = HIGH (parsed symbol or public DB exact match)
 * 2 = MEDIUM (closest-version match; needs runtime verification)
 * 1 = MISSING (not found statically)
 */

/* Runtime verification pseudocode (C) using kread primitives.
 * - Assumes functions available in your runtime: `int kread(vm_t addr, void *buf, size_t len)` and
 *   `uint64_t kread64(vm_t addr)` which return bytes from kernel memory.
 * - The verifier performs:
 *   1) signature scan in __TEXT_EXEC for common ARM64 prologues (STP x29,x30,...) and unique 32-byte
 *      signatures for target functions; validate by reading first bytes and comparing.
 *   2) reads `FALLBACK_AMFI_VM` memory region and probes likely offsets to detect `cs_enforcement_disable`
 *      by checking for boolean-like values and verifying callers reading/writing that offset.
 */

/* Example verifier (pseudocode) */
/*
int verify_and_fix_offsets()
{
    // helper lambdas (implement according to your runtime):
    // uint64_t kread64(vm) -> returns 64-bit value
    // int kread(vm, buf, len) -> reads kernel memory into buf, returns 0 on success

    // 1) Scan __TEXT_EXEC for candidate function prologues (fast heuristic)
    vm_t text_exec_base = /* from offsets_iPad8_9_17.3.1.json segments */ 0xfffffff007d40000ULL;
    size_t text_exec_size = /* from segments */ 0x2268000;

    // Example: scan for STP X29,X30 (0xa9bf7bfd is not literal; we compare instruction bytes)
    uint8_t buf[0x100];
    for (vm_t off = text_exec_base; off < text_exec_base + text_exec_size; off += 0x1000) {
        if (kread(off, buf, sizeof(buf)) != 0) continue;
        for (int i = 0; i < (int)sizeof(buf) - 8; i += 4) {
            // Check for typical function prologue bytes (STP X29,X30, [SP,#-0x20]! or similar)
            // Prologue pattern example (little-endian): 0xfd7b, b940 (varies). Instead, check for bytes sequence of stp x29,x30
            // This is a heuristic: you may want to match disassembly instead using Capstone in-process.
            if (/* buf[i..i+4] matches stp x29,x30 instruction encoding */ 0) continue;
            vm_t candidate = off + i;
            uint8_t sig32[32];
            if (kread(candidate, sig32, 32) != 0) continue;
            // Compare against known signatures (if any) or use further heuristics: look for bl/adrp references to strings etc.
            // If signature matches what we expect for vn_open/vnode_put, record candidate.
        }
    }

    // 2) Probe AMFI struct for cs_enforcement_disable offset
    // Read first 0x200 bytes of AMFI struct
    uint8_t amfi_buf[0x200];
    if (kread(FALLBACK_AMFI_VM, amfi_buf, sizeof(amfi_buf)) != 0) return -1;
    // Heuristic: cs_enforcement_disable is commonly a 32-bit or 8-bit flag near start of struct; scan for a boolean
    for (size_t off = 0; off < 0x200; off += 4) {
        uint32_t v = *(uint32_t *)(amfi_buf + off);
        if (v == 0 || v == 1) {
            // Further verify: search kernel text for code reading FALLBACK_AMFI_VM + off via LDR [Xn,#imm]
            // Find readers by scanning __TEXT_EXEC for ADRP + ADD/LDR patterns that resolve to (FALLBACK_AMFI_VM + off)
            // If a reader found, accept offset as VERIFIED.
        }
    }

    return 0;
}
*/

#endif /* RUNTIME_OFFSETS_FALLBACK_H */
