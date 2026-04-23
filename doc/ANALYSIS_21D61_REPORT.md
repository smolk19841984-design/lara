## 21D61 analysis report (offline, using existing scripts)

### Inputs used

- **Kernelcache (decompressed)**: `iPad8,9_Analysis/21D61/kernelcache_decompressed/kernelcache.release.ipad8.decompressed`
- **Sandbox kext (Mach-O)**: `iPad8,9_Analysis/Sandbox_Profiles/com.apple.security.sandbox.kext`
- **AMFI kext (Mach-O)**: `iPad8,9_Analysis/21D61/kernelcache_decompressed/kexts/com.apple.driver.AppleMobileFileIntegrity`
- **Symbols**: `iPad8,9_Analysis/21D61/symbols/kernelcache.release.iPad8,9_10_11_12.symbols.json`

### New: offline kernel-map harness

- **Harness script**: `scripts/offline_ios17_kernelmap.py`
  - Builds VM↔fileoff mapping from Mach-O segments/sections.
  - Validates sandbox candidates by byte-compare (`vm_read`) + section checks.
  - Writes canonical offsets JSON:
    - `iPad8,9_Analysis/21D61/verified_offsets.json`

### Script runs (what succeeded)

- **`Sandbox_Profiles/validate_sandbox_and_find_cs.py`**
  - Produced `analysis_outputs/validate_sandbox_and_find_cs.stdout.txt`
  - Many candidates were `match=True` (including 1, 5, 12).
  - Also scanned AMFI for `cs_enforcement*` strings.

- **`Sandbox_Profiles/decode_sandbox_kext.py com.apple.security.sandbox.kext`**
  - Successfully regenerated:
    - `Sandbox_Profiles/sandbox_strings.json`
    - `Sandbox_Profiles/sandbox_rules.txt`
    - `Sandbox_Profiles/sandbox_analysis_summary.txt`

- **`Sandbox_Profiles/find_cs_enforcement.py`**
  - Found the expected `cs_enforcement_disable` related strings inside AMFI’s `__TEXT.__cstring`
  - Output: `analysis_outputs/find_cs_enforcement.stdout.txt`

### Script runs (limitations observed)

- **`Sandbox_Profiles/find_cs_xrefs_adrp.py`**
  - Initially failed due to missing Python capstone; fixed by installing `python3-capstone` in WSL.
  - Current output: **no ADRP+ADD/LDR XREFs found** in `__TEXT_EXEC.__text` for the configured `TARGET_VM`.
  - This means the ADRP‑based xref approach, as currently parameterized, does **not** validate the target VM address via code references in that section.

### Invalid candidates found (offline)

Based on `Sandbox_Profiles/sandbox_validation_results.json`:

- **Candidate 7**: `match=false`
- **Candidate 8**: `match=false`

These candidates should be considered **invalid** for 21D61 until regenerated and revalidated.

### Kernel base (canonical)

From Mach-O kernelcache mapping (lowest segment `__TEXT` vmaddr):

- `KERNEL_BASE = 0xFFFFFFF007004000`

### Notes for project integration

- The sandbox-candidate validation provides **signature match evidence** (good signal).
- The AMFI `cs_enforcement_disable` logic currently has **string-based evidence**, but lacks a second independent confirmation method (the ADRP/XREF scan did not find a reference).
  - Policy: keep `cs_enforcement_disable` **Unverified** and gated/disabled by default until verified via symbol/xref/signature.

