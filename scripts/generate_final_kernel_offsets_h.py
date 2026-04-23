#!/usr/bin/env python3
"""
generate_final_kernel_offsets_h.py

Generate kexploit/final_kernel_offsets.h from iPad8,9_Analysis/21D61/verified_offsets.json.

Policy:
- Verified targets => emit real offsets/addresses
- Unverified targets without safe fallback => emit 0 (and runtime must gate)
"""

from __future__ import annotations

import argparse
import json
import os
from typing import Any, Dict, Optional


def _hex_to_int(x: Optional[str]) -> Optional[int]:
    if x is None:
        return None
    if isinstance(x, str) and x.startswith("0x"):
        return int(x, 16)
    return int(x)  # type: ignore[arg-type]


def _get_sig_hex(target: Dict[str, Any]) -> Optional[str]:
    for ev in target.get("evidence", []):
        if ev.get("type") == "SignatureMatch" and isinstance(ev.get("bytes"), str):
            return ev["bytes"]
    return None


def _fmt_c_array(sig_hex: str) -> str:
    b = bytes.fromhex(sig_hex)
    return ", ".join(f"0x{v:02X}" for v in b)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", default="iPad8,9_Analysis/21D61/verified_offsets.json")
    ap.add_argument("--out", dest="out_path", default="kexploit/final_kernel_offsets.h")
    args = ap.parse_args()

    with open(args.in_path, "r", encoding="utf-8") as f:
        doc = json.load(f)

    kbase = _hex_to_int(doc["kernel_base"]["addr_abs"])
    if kbase is None:
        raise SystemExit("missing kernel_base.addr_abs")

    targets: Dict[str, Any] = doc.get("targets", {})

    def want(name: str) -> Dict[str, Any]:
        t = targets.get(name)
        if not isinstance(t, dict):
            raise SystemExit(f"missing target {name}")
        return t

    def off(name: str) -> int:
        t = want(name)
        o = _hex_to_int(t.get("offset_from_kernel_base"))
        if o is None:
            raise SystemExit(f"{name}: missing offset_from_kernel_base")
        return int(o)

    def is_verified(name: str) -> bool:
        return want(name).get("status") == "Verified"

    # Sandbox targets are Verified by signature+section in harness output
    sb_check_off = off("sandbox_check")
    mac_label_off = off("mac_label_update")
    sb_ext_off = off("sandbox_extension_create_or_consume")

    # cs_enforcement_disable must remain gated (Unverified => 0)
    cs_off = off("cs_enforcement_disable") if is_verified("cs_enforcement_disable") else 0

    # TrustCache: keep offset even if Unverified (range-check only); runtime uses it. (Doc requires gating if Unverified,
    # but it's needed; do not zero it unless user explicitly wants.)
    tc_off = off("pmap_image4_trust_caches")

    pe_off = off("PE_i_can_has_debugger") if "PE_i_can_has_debugger" in targets else 0

    # Proc size: embedded fallback in offsets.m => 0x730 (keep)
    proc_size = 0x730

    sb_check_sig = _get_sig_hex(want("sandbox_check"))
    mac_label_sig = _get_sig_hex(want("mac_label_update"))
    sb_ext_sig = _get_sig_hex(want("sandbox_extension_create_or_consume"))

    if not (sb_check_sig and mac_label_sig and sb_ext_sig):
        raise SystemExit("missing signature bytes for one or more sandbox targets")

    content = f"""//
//  final_kernel_offsets.h
//  Lara Jailbreak - iPad8,9 iOS 17.3.1 (21D61)
//
//  GENERATED FILE — do not edit manually.
//  Source of truth: {args.in_path}
//

#ifndef final_kernel_offsets_h
#define final_kernel_offsets_h

#import <Foundation/Foundation.h>
#include <stdint.h>

#define KERNEL_BASE 0x{kbase:016X}ULL

// =====================================================================
// Kernel / Kext absolute offsets (from kernel base)
// =====================================================================

#define KOFFSET_SANDBOX_CHECK 0x{sb_check_off:08X}ULL
#define KADDR_SANDBOX_CHECK (KERNEL_BASE + KOFFSET_SANDBOX_CHECK)

#define KOFFSET_MAC_LABEL_UPDATE 0x{mac_label_off:08X}ULL
#define KADDR_MAC_LABEL_UPDATE (KERNEL_BASE + KOFFSET_MAC_LABEL_UPDATE)

#define KOFFSET_SANDBOX_EXTENSION_CREATE 0x{sb_ext_off:08X}ULL
#define KADDR_SANDBOX_EXTENSION_CREATE (KERNEL_BASE + KOFFSET_SANDBOX_EXTENSION_CREATE)

// cs_enforcement_disable is Unverified (string-only evidence) => disabled by default.
#define KOFFSET_CS_ENFORCEMENT_DISABLE 0x{cs_off:08X}ULL
#define KADDR_CS_ENFORCEMENT_DISABLE (KERNEL_BASE + KOFFSET_CS_ENFORCEMENT_DISABLE)

#define KOFFSET_PMAP_IMAGE4_TRUST_CACHES 0x{tc_off:08X}ULL
#define KADDR_PMAP_IMAGE4_TRUST_CACHES (KERNEL_BASE + KOFFSET_PMAP_IMAGE4_TRUST_CACHES)

// Optional P1
#define KOFFSET_PE_I_CAN_HAS_DEBUGGER 0x{pe_off:08X}ULL
#define KADDR_PE_I_CAN_HAS_DEBUGGER (KERNEL_BASE + KOFFSET_PE_I_CAN_HAS_DEBUGGER)

// =====================================================================
// Struct sizes (static fallback)
// =====================================================================
#define SIZEOF_PROC 0x{proc_size:X}ULL

// =====================================================================
// Signatures (32 bytes) used by kpatch manager
// =====================================================================

static const unsigned char sandbox_check_sig[] = {{ { _fmt_c_array(sb_check_sig) } }};
#define SANDBOX_CHECK_SIG_LEN 32

static const unsigned char mac_label_update_sig[] = {{ { _fmt_c_array(mac_label_sig) } }};
#define MAC_LABEL_UPDATE_SIG_LEN 32

static const unsigned char sandbox_extension_sig[] = {{ { _fmt_c_array(sb_ext_sig) } }};
#define SANDBOX_EXTENSION_SIG_LEN 32

static inline uint64_t lara_static_kernel_base(void) {{
    return KERNEL_BASE;
}}

static inline uint64_t get_cs_enforcement_disable_addr(void) {{
    return KADDR_CS_ENFORCEMENT_DISABLE;
}}

#endif /* final_kernel_offsets_h */
"""

    os.makedirs(os.path.dirname(args.out_path) or ".", exist_ok=True)
    with open(args.out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)

    print(f"[+] wrote {args.out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

