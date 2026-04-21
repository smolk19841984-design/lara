#!/usr/bin/env python3
import subprocess, shutil, sys
tools = ["ipsw", "apfs-fuse", "7z", "7zz", "dmg2img", "hfsplus"]
for t in tools:
    p = shutil.which(t)
    print(f"  {t}: {p or 'not found'}")
mods = ["lzma", "py7zr", "lzfse"]
for m in mods:
    try:
        __import__(m)
        print(f"  python {m}: ok")
    except ImportError:
        print(f"  python {m}: not installed")
print(f"  python: {sys.executable}")
