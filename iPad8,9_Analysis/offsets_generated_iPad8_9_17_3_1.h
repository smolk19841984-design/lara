/* Auto-generated offsets for iPad8,9 iOS 17.3.1 (21D61)
 * Collected from static analysis artifacts in the workspace.
 * Verify at runtime before applying patches.
 */
#ifndef OFFSETS_GENERATED_IPAD8_9_17_3_1_H
#define OFFSETS_GENERATED_IPAD8_9_17_3_1_H

#define KERNEL_BASE                   0xfffffff007004000ULL

/* Confirmed global symbol (AMFI) */
#define SYM_AMFI                      0xfffffff007c86ae0ULL
#define OFF_AMFI_FROM_BASE            0x00c82ae0ULL

/* allproc / rootvnode / kernel_task candidates (offsets from KERNEL_BASE)
 * These are candidates discovered by static scans in the repo. Verify in-memory. */
#define OFF_ALLPROC_CAND1             0x03216cc8ULL
#define OFF_ALLPROC_CAND2             0x011c4cf0ULL
#define ADDR_ALLPROC_CAND1            (KERNEL_BASE + OFF_ALLPROC_CAND1)
#define ADDR_ALLPROC_CAND2            (KERNEL_BASE + OFF_ALLPROC_CAND2)

#define OFF_ROOTVNODE_CAND1           0x031c3000ULL
#define OFF_ROOTVNODE_CAND2           0x0096b668ULL
#define OFF_ROOTVNODE_CAND3           0x032398b0ULL
#define ADDR_ROOTVNODE_CAND1          (KERNEL_BASE + OFF_ROOTVNODE_CAND1)

/* Kernel task / kernproc candidates (from offsets.json) */
#define OFF_KERNEL_TASK_CAND1         0x031ad400ULL
#define OFF_KERNEL_TASK_CAND2         0x0096b928ULL

/* Sandbox / MAC-related structure offsets (from tools/validate_offsets.py)
 * These are static guesses produced by the repo tooling. Runtime verify required. */
#define OFF_PROC_PROC_RO              0x18
#define OFF_PROC_RO_UCRED             0x20
#define OFF_UCRED_CR_LABEL            0x78
#define OFF_PROC_UID                  0x30
#define OFF_PROC_GID                  0x34
#define OFF_LABEL_SANDBOX             0x10
#define OFF_SANDBOX_EXT_SET           0x10
#define OFF_EXT_DATA                  0x40
#define OFF_EXT_DATALEN               0x48

/* Common proc/task offsets (conservative candidates) */
#define OFF_PROC_PID                  0x1C    /* candidate - verify with `p_comm` check */
#define OFF_PROC_TASK                 0x18    /* candidate - verify at runtime */

/* Patterns / signatures extracted from the kernel image (32 bytes) */
#define SIG_AMFI_BYTES                "\x24\xb1\x35\x01\x8d\xd7\x11\x80\x58\xb0\x35\x01\x1d\x3a\x11\x80\x6c\xaf\x35\x01\x90\xa3\x11\x80\xb4\xae\x35\x01\x0b\x24\x11\x80"
#define SIG_AMFI_MASKED_HEX           "24b135018dd7118058b035011d3a11806caf350190a31180b4ae35010b241180"

/* Panic signature (kept for completeness) */
#define SIG_PANIC_BYTES               "\x1c\x94\x79\x01\x5f\x06\x11\x80\xc0\x99\x79\x01\x99\x23\x11\x80\x34\x9b\x79\x01\x59\xd7\x11\x80\x48\x9b\x79\x01\x2d\x57\x11\x80"

/* Sandbox function signatures: not found in static symbol list; runtime search required.
 * Provide placeholders to be filled by dynamic signature extraction. */
#define ADDR_SANDBOX_CHECK_OFFSET     0x0    /* UNKNOWN - runtime search required */
#define ADDR_SANDBOX_EXTENSION_OFFSET 0x0    /* UNKNOWN - runtime search required */
#define PATTERN_SANDBOX_CHECK         ""     /* Provide first 16-32 bytes when located */
#define PATTERN_SANDBOX_AMFI_CHECK    ""     /* Pattern for AMFI check inside sandbox_check */

/* PPL / gadget hints: the repo contains `pmap_ppl_symbols_21D61.json` and
 * `ppl_ucred_analysis_21D61.json` with candidate symbols; specific gadgets
 * must be extracted from those files and verified live. */
#define PPL_GADGET_WRITE32_ADDR      0x0     /* Candidate PPL gadget (UNKNOWN) */

#endif /* OFFSETS_GENERATED_IPAD8_9_17_3_1_H */
