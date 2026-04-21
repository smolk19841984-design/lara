#!/usr/bin/env python3
import json, os, sys

SBX_OFFSETS = {
    "OFF_PROC_PROC_RO": 0x18,
    "OFF_PROC_RO_UCRED": 0x20,
    "OFF_UCRED_CR_LABEL": 0x78,
    "OFF_PROC_UID": 0x30,
    "OFF_PROC_GID": 0x34,
    "OFF_PROC_SVUID": 0x3c,
    "OFF_PROC_SVGID": 0x40,
    "OFF_PROC_PFLAG": 0x454,
    "OFF_UCRED_POSIX_CR_UID": 0x18,
    "OFF_UCRED_POSIX_CR_RUID": 0x1C,
    "OFF_UCRED_POSIX_CR_SVUID": 0x20,
    "OFF_UCRED_POSIX_CR_GID": 0x24,
    "OFF_UCRED_POSIX_CR_RGID": 0x26,
    "OFF_UCRED_POSIX_CR_GROUPS": 0x28,
    "OFF_UCRED_POSIX_CR_GMUID": 0x68,
    "OFF_UCRED_POSIX_CR_SVGID": 0x6C,
    "OFF_LABEL_SANDBOX": 0x10,
    "OFF_SANDBOX_EXT_SET": 0x10,
    "OFF_EXT_DATA": 0x40,
    "OFF_EXT_DATALEN": 0x48,
}

MAPPING_NAMES = {
    "OFF_PROC_PROC_RO": "off_proc_proc_ro",
    "OFF_PROC_RO_UCRED": "off_proc_ro_ucred",
    "OFF_UCRED_CR_LABEL": "off_ucred_cr_label",
    "OFF_LABEL_SANDBOX": "off_label_sandbox",
    "OFF_SANDBOX_EXT_SET": "off_sandbox_ext_set",
}

def load_mapping(base_dir):
    p = os.path.join(base_dir, "8ksec_archive", "mapping.json")
    if not os.path.exists(p):
        return {}
    with open(p) as f:
        content = f.read()
    offsets = {}
    for line in content.split("\n"):
        line = line.strip()
        if line.startswith("#define") and "off_" in line:
            parts = line.split()
            if len(parts) >= 3:
                try:
                    offsets[parts[1]] = int(parts[2], 0)
                except ValueError:
                    pass
    return offsets

def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    print("=" * 60)
    print("Firmware Offset Validation - iPad8,9 iOS 17.3.1 (21D61)")
    print("=" * 60)

    mapping = load_mapping(base_dir)
    print(f"\nLoaded {len(mapping)} offsets from mapping.json")

    confirmed = unverified = mismatched = 0
    for sbx_name, sbx_val in SBX_OFFSETS.items():
        map_name = MAPPING_NAMES.get(sbx_name)
        if map_name and map_name in mapping:
            if sbx_val == mapping[map_name]:
                print(f"  CONFIRMED: {sbx_name} = 0x{sbx_val:x}")
                confirmed += 1
            else:
                print(f"  MISMATCH: {sbx_name} = 0x{sbx_val:x} vs 0x{mapping[map_name]:x}")
                mismatched += 1
        else:
            print(f"  UNVERIFIED: {sbx_name} = 0x{sbx_val:x}")
            unverified += 1

    print(f"\nSummary: {confirmed} confirmed, {unverified} unverified, {mismatched} mismatched")

    # Check sandbox kext strings
    sp = os.path.join(base_dir, "research_new_method_sandbox_21D61.txt")
    if os.path.exists(sp):
        with open(sp) as f:
            sc = f.read()
        print("\nSandbox kext strings:")
        for s in ["CM_KERN_REQUEST_CONTAINER_ID", "CM_KERN_REQUEST_SYSTEM_CONTAINER_ID",
                   "sandbox_retain_persistent", "sandbox_release_persistent", "containermanagerd"]:
            print(f"  {'FOUND' if s in sc else 'NOT FOUND'}: {s}")

    print("\n" + "=" * 60)
    if mismatched > 0:
        print("VERDICT: MISMATCHES FOUND")
    elif confirmed >= 5:
        print("VERDICT: Core offsets confirmed - safe to test")
    else:
        print("VERDICT: Manual verification recommended")
    print("=" * 60)

if __name__ == "__main__":
    main()
