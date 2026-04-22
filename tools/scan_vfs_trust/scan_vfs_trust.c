/*
 * scan_vfs_trust.c — lightweight on-device kernel scanner (iOS 17.x / arm64e)
 *
 * Link with your jailbreak app and pass kread64 + kread_buf from the exploit.
 *
 * Notes:
 * - "FD 7B BF A9" is one common STP x29,x30 prologue; many unrelated functions
 *   share it. This tool reports multiple prologue hits and optional cstring
 *   matches so you can correlate with IDA/joker.
 * - Throttle: usleep(1000) every N reads to reduce watchdog pressure (not msleep,
 *   which is kernel-only on XNU).
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef uint64_t (*kread64_fn)(uint64_t addr);
typedef void (*kread_buf_fn)(uint64_t addr, void *buf, size_t len);

#define MH_MAGIC_64 0xfeedfacfu
#define LC_SEGMENT_64 0x19u
#define LC_FILESET_ENTRY 0x34u
#define MAX_LOADCMDS_BYTES (256u * 1024u)

struct mach_header_64 {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
};

struct segment_command_64 {
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
};

struct section_64 {
    char sectname[16];
    char segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
};

/* ARM64: stp x29, x30, [sp, #-0x10]! → bytes FD 7B BF A9 (LE insn 0xA9BF7BFD) */
#define ARM64_PROLOGUE_STP_FP_LR 0xA9BF7BFDu

#define DEFAULT_TEXT_SCAN_MAX (5UL * 1024 * 1024)
#define DEFAULT_DATA_SCAN_MAX (4UL * 1024 * 1024)
#define THROTTLE_EVERY 256u
#define STR_SCAN_CHUNK 4096u

static uint64_t g_text_vmaddr;
static uint64_t g_text_vmsize;
static uint64_t g_textexec_vmaddr;
static uint64_t g_textexec_vmsize;
static uint64_t g_dataconst_vmaddr;
static uint64_t g_dataconst_vmsize;
static bool g_have_textexec;
static bool g_have_dataconst;

static void throttle_reads(uint64_t *counter) {
    if (((*counter)++ % THROTTLE_EVERY) == 0)
        usleep(1000); /* 1 ms */
}

static bool kread_buf_safe(kread_buf_fn kb, uint64_t addr, void *buf, size_t len, uint64_t *th) {
    if (!kb || !buf || len == 0)
        return false;
    if (addr < 0xfffffff000000000ull || addr + len < addr)
        return false;
    kb(addr, buf, len);
    throttle_reads(th);
    return true;
}

static uint64_t kread64_safe(kread64_fn k64, uint64_t addr, uint64_t *th) {
    if (!k64)
        return 0;
    uint64_t v = k64(addr);
    throttle_reads(th);
    return v;
}

static uint32_t kread32_le(kread64_fn k64, uint64_t addr, uint64_t *th) {
    /* 4-byte aligned: lower 32 bits of LE qword */
    if (addr & 3u)
        return 0;
    return (uint32_t)(kread64_safe(k64, addr, th) & 0xffffffffu);
}

static uint8_t kread8_buf(kread_buf_fn kb, uint64_t addr, uint64_t *th) {
    uint8_t b = 0;
    if (!kb)
        return 0xff;
    kb(addr, &b, 1);
    throttle_reads(th);
    return b;
}

static int segname_eq(const char *a, const char *b) {
    return strncmp(a, b, 16) == 0;
}

/*
 * Walk Mach-O / fileset load commands at kernel base; fill segment bounds.
 * Falls back to scanning from kernel_base + skip header if parsing fails.
 */
static int parse_kernel_segments(kread64_fn k64, kread_buf_fn kb, uint64_t kbase, uint64_t *th) {
    uint8_t hdr[4096];
    if (!kread_buf_safe(kb, kbase, hdr, sizeof(hdr), th))
        return -1;

    struct mach_header_64 *mh = (struct mach_header_64 *)hdr;
    if (mh->magic != MH_MAGIC_64) {
        fprintf(stderr, "[!] No MH_MAGIC_64 at kernel_base (got 0x%08x)\n", mh->magic);
        return -1;
    }

    uint32_t off = (uint32_t)sizeof(struct mach_header_64);
    uint32_t ncmds = mh->ncmds;
    uint32_t limit = (uint32_t)sizeof(hdr);

    for (uint32_t i = 0; i < ncmds && off + 8 <= limit; i++) {
        uint32_t cmd = *(uint32_t *)(hdr + off);
        uint32_t cmdsize = *(uint32_t *)(hdr + off + 4);
        if (cmdsize < 8 || off + cmdsize > limit)
            break;

        if (cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)(hdr + off);
            if (segname_eq(seg->segname, "__TEXT")) {
                g_text_vmaddr = seg->vmaddr;
                g_text_vmsize = seg->vmsize;
            }
            if (strstr(seg->segname, "__TEXT_EXEC") != NULL || segname_eq(seg->segname, "__TEXT_EXEC")) {
                g_textexec_vmaddr = seg->vmaddr;
                g_textexec_vmsize = seg->vmsize;
                g_have_textexec = true;
            }
            if (strstr(seg->segname, "__DATA_CONST") != NULL || segname_eq(seg->segname, "__DATA_CONST")) {
                g_dataconst_vmaddr = seg->vmaddr;
                g_dataconst_vmsize = seg->vmsize;
                g_have_dataconst = true;
            }

            /* Sections inside segment */
            uint32_t sec_off = off + (uint32_t)sizeof(struct segment_command_64);
            for (uint32_t s = 0; s < seg->nsects && sec_off + sizeof(struct section_64) <= limit; s++) {
                struct section_64 *sec = (struct section_64 *)(hdr + sec_off);
                if (strstr(sec->sectname, "__text") != NULL && strstr(sec->segname, "__TEXT_EXEC") != NULL) {
                    g_textexec_vmaddr = sec->addr;
                    g_textexec_vmsize = sec->size;
                    g_have_textexec = true;
                }
                if (strstr(sec->sectname, "__const") != NULL && strstr(sec->segname, "__DATA_CONST") != NULL) {
                    g_dataconst_vmaddr = sec->addr;
                    g_dataconst_vmsize = sec->size;
                    g_have_dataconst = true;
                }
                sec_off += (uint32_t)sizeof(struct section_64);
            }
        }

        if (cmd == LC_FILESET_ENTRY) {
            /* Skip detailed fileset parsing; segment scan may still work from __TEXT */
        }

        off += cmdsize;
    }

    if (!g_have_textexec && g_text_vmaddr && g_text_vmsize) {
        g_textexec_vmaddr = g_text_vmaddr;
        g_textexec_vmsize = g_text_vmsize < DEFAULT_TEXT_SCAN_MAX ? g_text_vmsize : DEFAULT_TEXT_SCAN_MAX;
        g_have_textexec = true;
        fprintf(stderr, "[*] __TEXT_EXEC not found; using __TEXT subset for prologue scan\n");
    }

    if (!g_have_dataconst && g_text_vmaddr) {
        /* Last resort: small window after __TEXT (may miss; user can override) */
        g_dataconst_vmaddr = g_text_vmaddr + g_text_vmsize;
        g_dataconst_vmsize = DEFAULT_DATA_SCAN_MAX;
        g_have_dataconst = true;
        fprintf(stderr, "[*] __DATA_CONST not parsed; using heuristic window after __TEXT\n");
    }

    return 0;
}

static void scan_cs_enforcement(kread_buf_fn kb, uint64_t amfi_base, uint64_t *th) {
    const uint64_t struct_off = 0x170;
    uint64_t base = amfi_base + struct_off;

    fprintf(stderr, "\n=== CS enforcement (struct @ AMFI + 0x%llx) ===\n", (unsigned long long)struct_off);

    uint8_t row[16];
    if (!kread_buf_safe(kb, base + 0x40, row, sizeof(row), th)) {
        fprintf(stderr, "[!] kread failed around struct+0x40\n");
        return;
    }

    uint8_t b50 = kread8_buf(kb, base + 0x50, th);
    uint8_t b54 = kread8_buf(kb, base + 0x54, th);
    uint8_t b58 = kread8_buf(kb, base + 0x58, th);

    fprintf(stderr, "  bytes @ +0x40..+0x4f: ");
    for (int i = 0; i < 16; i++)
        fprintf(stderr, "%02x ", row[i]);
    fprintf(stderr, "\n");
    fprintf(stderr, "  byte @ +0x50: %u  +0x54: %u  +0x58: %u\n", b50, b54, b58);

    if (b50 <= 1u && b54 <= 1u && b58 <= 1u) {
        printf("[OK] cs_enforcement_disable candidates: bytes at +0x50/+0x54/+0x58 are 0/1 (struct base 0x%016" PRIx64 ")\n",
               base);
        printf("#define CS_ENFORCEMENT_STRUCT_BASE  0x%016" PRIx64 "ULL /* AMFI + 0x170 */\n", base);
        printf("#define CS_ENFORCEMENT_OFFSET         0x50 /* confirmed (field in struct) */\n");
    } else {
        printf("[?] Pattern not clearly boolean at +0x50/+0x54/+0x58 — verify in IDA\n");
    }
}

static void scan_prologue_hits(kread64_fn k64, uint64_t text_start, uint64_t text_len, uint64_t *th, int max_hits) {
    fprintf(stderr, "\n=== ARM64 prologue 0xA9BF7BFD (FD 7B BF A9) in __TEXT_EXEC (max %d hits) ===\n", max_hits);

    uint64_t end = text_start + text_len;
    if (text_len > DEFAULT_TEXT_SCAN_MAX)
        end = text_start + DEFAULT_TEXT_SCAN_MAX;

    int found = 0;
    for (uint64_t a = text_start; a + 4 <= end && found < max_hits; a += 4) {
        uint32_t ins = kread32_le(k64, a, th);
        if (ins == ARM64_PROLOGUE_STP_FP_LR) {
            printf("#define VFS_PROLOGUE_HIT_%02d     0x%016" PRIx64 "ULL\n", found + 1, a);
            fprintf(stderr, "  hit %d @ 0x%016" PRIx64 "\n", found + 1, a);
            found++;
        }
    }

    if (found == 0)
        fprintf(stderr, "[!] No prologue hits (wrong TEXT range?)\n");
    else
        fprintf(stderr, "[*] These are NOT uniquely vn_open/vn_write/... — use symbols or longer signatures.\n");
}

static int find_substring_in_range(kread_buf_fn kb, uint64_t start, uint64_t len, const char *needle, uint64_t *th,
                                   uint64_t *out_addr) {
    size_t nl = strlen(needle);
    if (nl == 0 || len < nl)
        return -1;

    uint8_t buf[STR_SCAN_CHUNK];
    for (uint64_t off = 0; off + nl <= len; off += STR_SCAN_CHUNK - nl) {
        uint64_t chunk = len - off > STR_SCAN_CHUNK ? STR_SCAN_CHUNK : (len - off);
        if (!kread_buf_safe(kb, start + off, buf, (size_t)chunk, th))
            return -1;
        for (size_t i = 0; i + nl <= chunk; i++) {
            if (memcmp(buf + i, needle, nl) == 0) {
                *out_addr = start + off + i;
                return 0;
            }
        }
    }
    return -1;
}

static void scan_cstrings(kread_buf_fn kb, uint64_t text_lo, uint64_t text_len, uint64_t *th) {
    static const char *const names[] = {
        "vn_open",
        "vn_write",
        "vn_close",
        "vfs_context_current",
        "vnode_put",
        "pmap_image4_trust_caches",
        "kern_trustcache",
    };

    fprintf(stderr, "\n=== C string scan (same range as TEXT scan; best-effort) ===\n");

    for (size_t n = 0; n < sizeof(names) / sizeof(names[0]); n++) {
        uint64_t sa = 0;
        if (find_substring_in_range(kb, text_lo, text_len, names[n], th, &sa) == 0) {
            printf("#define CSTR_%s 0x%016" PRIx64 "ULL\n", names[n], sa);
            fprintf(stderr, "  \"%s\" @ 0x%016" PRIx64 "\n", names[n], sa);
        } else {
            fprintf(stderr, "  (not found in range) \"%s\"\n", names[n]);
        }
    }
}

static bool trustcache_hdr_plausible(kread64_fn k64, uint64_t ptr, uint64_t *th) {
    if (ptr < 0xfffffff000000000ull)
        return false;
    uint32_t ver = kread32_le(k64, ptr, th);
    if (ver != 1u)
        return false;
    uint32_t nh = kread32_le(k64, ptr + 0x14u, th); /* after uuid: rough */
    /* trust_cache_v1: version, uuid[16], num_hashes at +0x14 */
    nh = kread32_le(k64, ptr + 0x14u, th);
    return nh > 0 && nh < 500000u;
}

static void scan_trustcache_pointers(kread64_fn k64, kread_buf_fn kb, uint64_t dstart, uint64_t dlen, uint64_t *th) {
    fprintf(stderr, "\n=== Trust cache pointer scan (__DATA_CONST heuristic) ===\n");

    uint64_t end = dstart + (dlen > DEFAULT_DATA_SCAN_MAX ? DEFAULT_DATA_SCAN_MAX : dlen);
    int found = 0;

    for (uint64_t a = dstart; a + 8 <= end && found < 8; a += 8) {
        uint64_t p = kread64_safe(k64, a, th);
        if (!trustcache_hdr_plausible(k64, p, th))
            continue;
        printf("#define TRUSTCACHE_HDR_PTR_%d     0x%016" PRIx64 "ULL /* points to 0x%016" PRIx64 " */\n", found + 1, a,
               p);
        fprintf(stderr, "  slot @ 0x%016" PRIx64 " -> hdr 0x%016" PRIx64 "\n", a, p);
        found++;
    }

    if (found == 0)
        fprintf(stderr, "[!] No plausible trustcache v1 headers found — expand DATA_CONST or verify layout\n");
}

/*
 * Public API: call from your app after kernel R/W is ready.
 */
void scan_vfs_trust_run(uint64_t kernel_base, uint64_t amfi_base, kread64_fn k64, kread_buf_fn kbuf) {
    uint64_t th = 0;

    memset(&g_text_vmaddr, 0, sizeof(g_text_vmaddr));
    g_have_textexec = g_have_dataconst = false;

    if (parse_kernel_segments(k64, kbuf, kernel_base, &th) != 0) {
        fprintf(stderr, "[*] Mach-O parse failed; using kernel_base + 0x8000, len 5MB for TEXT\n");
        g_textexec_vmaddr = kernel_base + 0x8000;
        g_textexec_vmsize = DEFAULT_TEXT_SCAN_MAX;
        g_have_textexec = true;
        g_dataconst_vmaddr = kernel_base + 0x10000000ull; /* heuristic */
        g_dataconst_vmsize = DEFAULT_DATA_SCAN_MAX;
        g_have_dataconst = true;
    }

    printf("/* scan_vfs_trust — kernel_base=0x%016" PRIx64 " amfi_base=0x%016" PRIx64 " */\n", kernel_base, amfi_base);

    scan_cs_enforcement(kbuf, amfi_base, &th);

    if (g_have_textexec)
        scan_prologue_hits(k64, g_textexec_vmaddr, g_textexec_vmsize, &th, 32);

    if (g_have_textexec)
        scan_cstrings(kbuf, g_textexec_vmaddr, g_textexec_vmsize < DEFAULT_TEXT_SCAN_MAX ? g_textexec_vmsize : DEFAULT_TEXT_SCAN_MAX, &th);

    if (g_have_dataconst)
        scan_trustcache_pointers(k64, kbuf, g_dataconst_vmaddr, g_dataconst_vmsize, &th);

    printf("/* End */\n");
}

/* Optional standalone test driver — do not link in production or provide stub kreads */
#if defined(SCAN_VFS_TRUST_STANDALONE_MAIN)
static uint64_t stub_kread64(uint64_t a) {
    (void)a;
    return 0;
}
static void stub_kbuf(uint64_t a, void *b, size_t n) {
    (void)a;
    (void)b;
    (void)n;
}
int main(void) {
    fprintf(stderr, "Build without SCAN_VFS_TRUST_STANDALONE_MAIN and link real kreads.\n");
    scan_vfs_trust_run(0xfffffff00da40000ull, 0xfffffff00e6c2ae0ull, stub_kread64, stub_kbuf);
    return 0;
}
#endif
