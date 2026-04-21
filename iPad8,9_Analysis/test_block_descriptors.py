#!/usr/bin/env python3
"""
Offline test for block descriptor support in ds_kvtophys/ds_kvtopte.
Tests ARM64 16KB page table walk simulation for iPad8,9 iOS 17.3.1.
"""

import struct
import os

# Constants for ARM64 16KB granule
ARM64_16K_SHIFT = 14
ARM64_16K_SIZE = 1 << ARM64_16K_SHIFT
ARM64_16K_MASK = ARM64_16K_SIZE - 1

L1_IDX_SHIFT = 36
L2_IDX_SHIFT = 25
L3_IDX_SHIFT = 14

TTE_TYPE_TABLE = 0x3
TTE_TYPE_BLOCK = 0x1
TTE_VALID = 0x1

L1_BLOCK_PA_MASK = 0x0000FFF000000000
L1_BLOCK_OFFSET_MASK = 0x0000000FFFFFFFFF
L2_BLOCK_PA_MASK = 0x0000FFFFE0000000
L2_BLOCK_OFFSET_MASK = 0x000000001FFFFFFF

def PTE_TO_PA(pte):
    return pte & 0x0000FFFFFFFFC000

def L1_IDX(va):
    return (va >> L1_IDX_SHIFT) & 0x7FF

def L2_IDX(va):
    return (va >> L2_IDX_SHIFT) & 0x7FF

def L3_IDX(va):
    return (va >> L3_IDX_SHIFT) & 0x7FF

TEST_ADDRESSES = [
    ("Kernel base (slide=0)", 0xfffffff007004000),
    ("Kernel text + 1MB", 0xfffffff007104000),
    ("Kernel text + 16MB", 0xfffffff008004000),
    ("Kernel data", 0xfffffff008000000),
    ("Kernel heap area", 0xfffffff019310000),
    ("Kernel heap + 16MB", 0xfffffff01a310000),
    ("Physical aperture", 0xffffffe000000000),
    ("PPL sequester zone", 0xffffffe009000000),
    ("Kernel zone 0xffffffe2", 0xffffffe200000000),
]

def test_block_descriptor_logic():
    print("=" * 70)
    print("TEST 1: Block Descriptor Address Calculation")
    print("=" * 70)

    l1_block_pa = 0x80000000
    l1_block_desc = (l1_block_pa & L1_BLOCK_PA_MASK) | TTE_TYPE_BLOCK | TTE_VALID
    test_kva = 0xfffffff007004000
    offset = test_kva & L1_BLOCK_OFFSET_MASK
    expected_pa = (l1_block_desc & L1_BLOCK_PA_MASK) | offset

    print("L1 block descriptor: 0x%016x" % l1_block_desc)
    t = "BLOCK" if (l1_block_desc & TTE_TYPE_BLOCK) == TTE_TYPE_BLOCK else "TABLE"
    print("  Type: %s" % t)
    print("  Valid: %s" % bool(l1_block_desc & TTE_VALID))
    print("  PA base: 0x%016x" % (l1_block_desc & L1_BLOCK_PA_MASK))
    print("Test KVA: 0x%016x" % test_kva)
    print("  L1 index: %d" % L1_IDX(test_kva))
    print("  Offset within 1TB block: 0x%08x" % offset)
    print("Calculated PA: 0x%016x" % expected_pa)
    print()

    l2_block_pa = 0x80000000
    l2_block_desc = (l2_block_pa & L2_BLOCK_PA_MASK) | TTE_TYPE_BLOCK | TTE_VALID
    test_kva2 = 0xfffffff007104000
    offset2 = test_kva2 & L2_BLOCK_OFFSET_MASK
    expected_pa2 = (l2_block_desc & L2_BLOCK_PA_MASK) | offset2

    print("L2 block descriptor: 0x%016x" % l2_block_desc)
    t2 = "BLOCK" if (l2_block_desc & TTE_TYPE_BLOCK) == TTE_TYPE_BLOCK else "TABLE"
    print("  Type: %s" % t2)
    print("  Valid: %s" % bool(l2_block_desc & TTE_VALID))
    print("  PA base: 0x%016x" % (l2_block_desc & L2_BLOCK_PA_MASK))
    print("Test KVA: 0x%016x" % test_kva2)
    print("  L1 index: %d" % L1_IDX(test_kva2))
    print("  L2 index: %d" % L2_IDX(test_kva2))
    print("  Offset within 512MB block: 0x%08x" % offset2)
    print("Calculated PA: 0x%016x" % expected_pa2)
    print()

    print("XPRR bit position verification:")
    print("  XPRR bits are at [59:57] for both PTE and block descriptors")
    print("  L1 block descriptor XPRR: %d" % ((l1_block_desc >> 57) & 0x7))
    print("  L2 block descriptor XPRR: %d" % ((l2_block_desc >> 57) & 0x7))
    print()

def test_kernel_address_ranges():
    print("=" * 70)
    print("TEST 2: Kernel Address Range Analysis")
    print("=" * 70)
    print()
    print("For iOS 17 arm64e with 16KB granule:")
    print("  L1 covers 1 TB per entry (bits[47:36] of VA)")
    print("  L2 covers 512 MB per entry (bits[47:25] of VA)")
    print("  L3 covers 16 KB per entry (bits[47:14] of VA)")
    print()

    for name, addr in TEST_ADDRESSES:
        l1_idx = L1_IDX(addr)
        l2_idx = L2_IDX(addr)
        l3_idx = L3_IDX(addr)

        if addr >= 0xfffffff000000000:
            region = "Kernel static (slid)"
        elif addr >= 0xffffffe000000000:
            region = "Physical aperture"
        elif addr >= 0xffffffe200000000:
            region = "Kernel heap/zone"
        else:
            region = "Unknown"

        print("%s:" % name)
        print("  Address: 0x%016x" % addr)
        print("  Region: %s" % region)
        print("  L1 index: %d (0x%03x)" % (l1_idx, l1_idx))
        print("  L2 index: %d (0x%03x)" % (l2_idx, l2_idx))
        print("  L3 index: %d (0x%03x)" % (l3_idx, l3_idx))
        print()

def test_xprr_permissions():
    print("=" * 70)
    print("TEST 3: XPRR Permission Bit Manipulation")
    print("=" * 70)
    print()

    XPRR_KERN_RO_PERM = 0
    XPRR_KERN_RW_PERM = 1
    XPRR_KERN_RX_PERM = 2
    XPRR_PPL_RW_PERM = 3
    XPRR_PPL_RX_PERM = 4

    base_desc = 0x80000001
    base_desc |= (XPRR_PPL_RW_PERM << 57)

    print("Original block descriptor: 0x%016x" % base_desc)
    print("  XPRR: %d (PPL_RW)" % ((base_desc >> 57) & 0x7))
    print()

    new_perm = XPRR_KERN_RW_PERM
    new_desc = base_desc & ~(0x7 << 57)
    new_desc |= (new_perm << 57)

    print("Modified block descriptor: 0x%016x" % new_desc)
    print("  XPRR: %d (KERN_RW)" % ((new_desc >> 57) & 0x7))
    print()

    verify_xprr = (new_desc >> 57) & 0x7
    assert verify_xprr == new_perm, "XPRR mismatch: %d != %d" % (verify_xprr, new_perm)
    print("XPRR modification verified successfully!")
    print()

def test_mask_correctness():
    print("=" * 70)
    print("TEST 4: Block Descriptor Mask Verification")
    print("=" * 70)
    print()

    l1_pa_bits = 47 - 36 + 1
    l1_offset_bits = 36

    print("L1 block descriptor:")
    print("  PA bits: [47:36] = %d bits" % l1_pa_bits)
    print("  Offset bits: [35:0] = %d bits" % l1_offset_bits)
    print("  Block size: 2^%d = %d bytes = %d TB" % (l1_offset_bits, 1 << l1_offset_bits, (1 << l1_offset_bits) >> 40))
    print("  PA mask: 0x%016x" % L1_BLOCK_PA_MASK)
    print("  Offset mask: 0x%016x" % L1_BLOCK_OFFSET_MASK)
    print()

    l2_pa_bits = 47 - 25 + 1
    l2_offset_bits = 25

    print("L2 block descriptor:")
    print("  PA bits: [47:25] = %d bits" % l2_pa_bits)
    print("  Offset bits: [24:0] = %d bits" % l2_offset_bits)
    print("  Block size: 2^%d = %d bytes = %d MB" % (l2_offset_bits, 1 << l2_offset_bits, (1 << l2_offset_bits) >> 20))
    print("  PA mask: 0x%016x" % L2_BLOCK_PA_MASK)
    print("  Offset mask: 0x%016x" % L2_BLOCK_OFFSET_MASK)
    print()

    assert (L1_BLOCK_PA_MASK & L1_BLOCK_OFFSET_MASK) == 0, "L1 masks overlap!"
    assert (L2_BLOCK_PA_MASK & L2_BLOCK_OFFSET_MASK) == 0, "L2 masks overlap!"
    assert (L1_BLOCK_PA_MASK | L1_BLOCK_OFFSET_MASK) == 0x0000FFFFFFFFFFFF, "L1 masks dont cover full range!"
    assert (L2_BLOCK_PA_MASK | L2_BLOCK_OFFSET_MASK) == 0x0000FFFFFFFFFFFF, "L2 masks dont cover full range!"
    print("All mask verifications passed!")
    print()

def test_kernelcache_static_analysis():
    print("=" * 70)
    print("TEST 5: Kernelcache Static Analysis")
    print("=" * 70)
    print()

    kc_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "21D61", "kernelcache.decompressed")

    if not os.path.exists(kc_path):
        print("Kernelcache not found at: %s" % kc_path)
        print("Skipping static analysis.")
        return

    file_size = os.path.getsize(kc_path)
    print("Kernelcache size: %d bytes (%.1f MB)" % (file_size, file_size / (1024*1024)))

    with open(kc_path, 'rb') as f:
        magic = struct.unpack('<I', f.read(4))[0]
        if magic == 0xFEEDFACF:
            print("Mach-O magic: 0x%08x (64-bit)" % magic)
            cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack('<IIIIII', f.read(24))
            print("CPU type: 0x%x (ARM64e = 0x100000C)" % cputype)
            print("File type: 0x%x (EXECUTE = 0x2)" % filetype)
            print("Number of commands: %d" % ncmds)
        else:
            print("Unknown magic: 0x%08x" % magic)
            return

    print()
    print("Note: Page tables are created at runtime by XNU.")
    print("Static analysis cannot determine actual page table layout.")
    print("However, XNU source code shows:")
    print("  - Kernel __TEXT is typically mapped with L2 block descriptors (512 MB)")
    print("  - Kernel __DATA is typically mapped with L2 block descriptors (512 MB)")
    print("  - Kernel heap uses L3 page entries (16 KB)")
    print()

def test_ds_kvtopte_addr_logic():
    print("=" * 70)
    print("TEST 6: ds_kvtopte_addr Address Calculation")
    print("=" * 70)
    print()

    l1_table_va = 0xfffffff007200000
    test_kva = 0xfffffff007004000
    l1_idx = L1_IDX(test_kva)
    l1_block_addr = l1_table_va + l1_idx * 8
    print("L1 table VA: 0x%016x" % l1_table_va)
    print("Test KVA: 0x%016x" % test_kva)
    print("L1 index: %d" % l1_idx)
    print("L1 block descriptor address: 0x%016x" % l1_block_addr)
    print()

    l2_table_va = 0xfffffff007300000
    l2_idx = L2_IDX(test_kva)
    l2_block_addr = l2_table_va + l2_idx * 8
    print("L2 table VA: 0x%016x" % l2_table_va)
    print("L2 index: %d" % l2_idx)
    print("L2 block descriptor address: 0x%016x" % l2_block_addr)
    print()

    print("ds_kvtopte_addr should return these addresses for modification.")
    print()

if __name__ == "__main__":
    print()
    print("=" * 70)
    print("BLOCK DESCRIPTOR SUPPORT - OFFLINE TESTS")
    print("iPad8,9 iOS 17.3.1 (21D61) - ARM64 16KB Granule")
    print("=" * 70)
    print()

    test_block_descriptor_logic()
    test_kernel_address_ranges()
    test_xprr_permissions()
    test_mask_correctness()
    test_kernelcache_static_analysis()
    test_ds_kvtopte_addr_logic()

    print("=" * 70)
    print("ALL TESTS COMPLETED")
    print("=" * 70)
