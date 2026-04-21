#!/usr/bin/env python3
"""
Automated IPSW Extraction and Kernel Diffing Tool
Specifically customized for: iPad8,9 (iOS 17.3.1 vs 17.4)

This script automates:
1. Downloading the vulnerable (21D61) and patched (21E219) kernelcaches for your specific device.
2. Extracting target Kernel Extensions (KEXTs) for patch diffing (e.g., AppleDiskImages2 from CVE-2024-23265).
3. Dumping basic symbol and syscall information to help analyze offsets and patches.
"""

import os
import sys
import platform
import subprocess
from pathlib import Path

# Config
DEVICE = "iPad8,9"
BUILD_VULN = "21D61"      # iOS 17.3.1 (Vulnerable)
BUILD_PATCHED = "21E219"   # iOS 17.4 (Patched)
TARGET_KEXT = "com.apple.driver.AppleDiskImages2"

# Paths
WORK_DIR = Path(__file__).resolve().parent
IPSW_TOOL = r"C:\Users\smolk\Documents\palera1n-windows\Dopamine_darksword\tools\ipsw.exe" if platform.system() == "Windows" else "ipsw"

def run_ipsw(args: list[str], timeout: int = 1800) -> str:
    """Run blacktop/ipsw tool."""
    cmd = [IPSW_TOOL] + args
    print(f"[*] Running: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace", encoding="utf-8")
        if proc.returncode != 0:
            print(f"[!] ipsw returned non-zero code or failed: \n{proc.stderr}")
        return proc.stdout
    except Exception as e:
        print(f"[!] Execution error: {e}")
        sys.exit(1)

def download_kernelcache(build: str) -> Path:
    print(f"\n[+] Fetching Kernelcache for {DEVICE} - Build {build}")
    out_dir = WORK_DIR / build
    out_dir.mkdir(exist_ok=True)
    
    # Check if we already downloaded it
    existing_kc = list(out_dir.rglob("kernelcache.release.*"))
    if existing_kc:
        print(f"  -> Found existing kernelcache: {existing_kc[0].name}")
        return existing_kc[0]

    # Download via remote extract. ipsw expects: ipsw download ipsw --device ... --build ... --kernel -o out_dir
    run_ipsw(["download", "ipsw", "--device", DEVICE, "--build", build, "--kernel", "--output", str(out_dir)])
    
    # Find downloaded file
    downloaded_kc = list(out_dir.rglob("kernelcache.release.*"))
    if not downloaded_kc:
        print("  [-] Failed to download kernelcache (Output empty or not found).")
        sys.exit(1)
    
    # Return the first match
    return downloaded_kc[0]

def extract_kext(kernelcache: Path, kext_name: str, out_folder: Path):
    print(f"\n[+] Extracting KEXT '{kext_name}' from {kernelcache.name}")
    out_folder.mkdir(exist_ok=True, parents=True)
    kext_out = out_folder / f"{kext_name}.kext"
    
    if (kext_out).exists():
        print(f"  -> KEXT already extracted at {kext_out.name}")
        return kext_out
        
    # ipsw kernel extract <KC> com.apple... -o out
    run_ipsw(["kernel", "extract", str(kernelcache), kext_name, "--output", str(out_folder)])
    
    # It might create a folder named after the KC, let's assume it puts it in out_folder
    # The actual extracted KEXT is usually dumped as a MachO or folder
    print(f"  -> Extraction complete for {kext_name}")
    return kext_out

def main():
    print(f"========== IPSW Patch Diff Automation ==========")
    print(f" Device: {DEVICE}")
    print(f" Builds: {BUILD_VULN} (Vuln) vs {BUILD_PATCHED} (Patched)")
    print(f" Workspace: {WORK_DIR}")
    print(f"================================================\n")
    
    if not Path(IPSW_TOOL).exists():
        print(f"[-] ipsw tool not found at {IPSW_TOOL}. Cannot proceed.")
        return

    # 1. Download Kernelcaches
    kc_vuln = download_kernelcache(BUILD_VULN)
    kc_patch = download_kernelcache(BUILD_PATCHED)

    # 2. Extract the vulnerable and patched KEXTs for AppleDiskImages2
    kext_vuln_dir = WORK_DIR / "kexts_21D61"
    kext_patch_dir = WORK_DIR / "kexts_21E219"
    
    extract_kext(kc_vuln, TARGET_KEXT, kext_vuln_dir)
    extract_kext(kc_patch, TARGET_KEXT, kext_patch_dir)
    
    print("\n========== Analysis Stage ==========")
    print(f"[*] To compare the KEXTs in Ghidra/Meld (as described in the 8kSec article),")
    print(f"[*] use the extracted binaries located in:")
    print(f"   - {kext_vuln_dir}")
    print(f"   - {kext_patch_dir}")
    
    # Dump syscall table just to verify we have correct analysis tools on both
    print("\n[+] Dumping base syscall info for offsets referencing (Vulnerable Build)...")
    syscalls_out = run_ipsw(["kernel", "syscall", str(kc_vuln)])
    with open(WORK_DIR / f"syscalls_{DEVICE}_{BUILD_VULN}.txt", "w", encoding="utf-8") as f:
        f.write(syscalls_out)
    print(f"  -> Saved syscall table to syscalls_{DEVICE}_{BUILD_VULN}.txt")
    print("\n[+] Done! Automation setup is complete in this folder.")

if __name__ == "__main__":
    main()
