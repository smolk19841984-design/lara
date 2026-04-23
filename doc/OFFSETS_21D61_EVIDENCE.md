## OFFSETS 21D61 — evidence (offline harness)

Источник требований: `doc/AI_TASK_OFFSETS_21D61.md`.

Каноничный JSON (source of truth):

- `iPad8,9_Analysis/21D61/verified_offsets.json`

Генерация runtime‑header:

- `scripts/generate_final_kernel_offsets_h.py` → `kexploit/final_kernel_offsets.h`

### Kernel base

- **kernel_base**: `0xFFFFFFF007004000` (**Verified**)
  - Evidence: извлечено из Mach‑O kernelcache (минимальный `vmaddr` у `__TEXT` сегмента).

### Sandbox kext targets (`com.apple.security.sandbox.kext`)

Все sandbox‑цели ниже подтверждены офлайн‑валидацией через harness:

- **sandbox_check** (**Verified**)
  - addr: `0xFFFFFFF009E023A8`
  - offset_from_kernel_base: `0x02DFE3A8`
  - section: `__TEXT_EXEC.__text`
  - evidence: SignatureMatch (32 bytes) + SectionCheck

- **mac_label_update** (**Verified**)
  - addr: `0xFFFFFFF009E06388`
  - offset_from_kernel_base: `0x02E02388`
  - section: `__TEXT_EXEC.__text`
  - evidence: SignatureMatch (32 bytes) + SectionCheck

- **sandbox_extension_create_or_consume** (**Verified**)
  - addr: `0xFFFFFFF009E26A0C`
  - offset_from_kernel_base: `0x02E22A0C`
  - section: `__TEXT_EXEC.__text`
  - evidence: SignatureMatch (32 bytes) + SectionCheck

### AMFI target (`com.apple.driver.AppleMobileFileIntegrity`)

- **cs_enforcement_disable** (**Unverified**)
  - hypothesis addr: `0xFFFFFFF0079339A0`
  - offset_from_kernel_base: `0x0092F9A0`
  - evidence: StringEvidence (`cs_enforcement_disable` present in binary)
  - note: ADRP/XREF proof отсутствует → runtime‑патч должен быть gated/disabled по умолчанию.

### TrustCache

- **pmap_image4_trust_caches** (**Unverified**)
  - addr: `0xFFFFFFF007AC2968`
  - offset_from_kernel_base: `0x00ABE968`
  - evidence: RangeCheck (адрес маппится в kernelcache VM↔fileoff)

### Kernel symbols / struct size (runtime fallbacks)

Пока только range‑check + fallback‑evidence (без symbol/xref/signature доказательств):

- **_kernproc**: `0xFFFFFFF00796F928` (offset `0x0096B928`) — **Unverified**
- **_rootvnode**: `0xFFFFFFF00A217640` (offset `0x03213640`) — **Unverified**
- **_allproc**: runtime fallback — **Unverified**
- **kernelStruct.proc.struct_size**: `0x730` — **Unverified**

### Rejected sandbox candidates

Candidate **7** и **8** — **Rejected** (signature mismatch) и не должны использоваться как источники “важных” оффсетов.

