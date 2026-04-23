## OFFSETS 21D61 — evidence snapshot (offset/)

Источник требований: `doc/AI_TASK_OFFSETS_21D61.md`.

### Каноничный вход (source of truth)

- `offset/verified_offsets_21D61.json`

### Kernel base

- **kernel_base**: `0xFFFFFFF007004000` (**Verified**)
  - Evidence: derived from Mach-O kernelcache mapping (lowest segment `vmaddr`).

### Sandbox (com.apple.security.sandbox.kext)

- **sandbox_check**: `KBASE + 0x02DFE3A8` → `0xFFFFFFF009E023A8` (**Verified**)
  - Evidence: signature match, `sandbox_validation_results.json` candidate **1**, `match=true`
- **mac_label_update**: `KBASE + 0x02E02388` → `0xFFFFFFF009E06388` (**Verified**)
  - Evidence: signature match, `sandbox_validation_results.json` candidate **5**, `match=true`
- **sandbox_extension_create_or_consume**: `KBASE + 0x02E22A0C` → `0xFFFFFFF009E26A0C` (**Verified**)
  - Evidence: signature match from existing validation run, candidate **12**, `match=true`

### AMFI (com.apple.driver.AppleMobileFileIntegrity)

- **cs_enforcement_disable**: `KBASE + 0x0092F9A0` → `0xFFFFFFF0079339A0` (**Unverified**)
  - Evidence: string hit in AMFI `__TEXT.__cstring` (`analysis_outputs/find_cs_enforcement.stdout.txt`)
  - Counter‑evidence: no ADRP+ADD/LDR xrefs found by current scanner (`analysis_outputs/find_cs_xrefs_adrp.stdout.txt`)
  - Policy: **must not be treated Verified** until a second independent proof exists (symbol/xref/signature).

### TrustCache

- **pmap_image4_trust_caches**: `KBASE + 0x00ABE968` → `0xFFFFFFF007AC2968` (**Unverified**)
  - Evidence: address maps to fileoff in kernelcache VM↔fileoff map (harness RangeCheck).

### Kernel symbols / struct sizes (static fallbacks present in runtime)

These are present as static fallbacks in `kexploit/offsets.m` for build 21D61 but do not yet have offline signature/symbol proof in repo artifacts.

- **_kernproc**: `KBASE + 0x0096B928` → `0xFFFFFFF00796B928` (**Unverified**)
- **_rootvnode**: `KBASE + 0x03213640` → `0xFFFFFFF00A217640` (**Unverified**)
- **kernelStruct.proc.struct_size**: `0x730` (**Unverified**)
- **_allproc**: runtime fallback target (**Unverified**, no offline addr recorded here)

### Rejected sandbox candidates

From `iPad8,9_Analysis/Sandbox_Profiles/sandbox_validation_results.json`:

- Candidate **7**: `match=false` → **Rejected**
- Candidate **8**: `match=false` → **Rejected**

