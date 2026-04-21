#!/usr/bin/env python3
"""Generate ds_kread64 commands / formulas to walk ARM64 stage-1 page tables.

Usage examples:
  python compute_pte_addresses.py --va 0xfffffff0082231f8 --root 0xfffffff019ba8000 --phys2virt 0xffffffe816000000 --root-level 1

This prints the L1/L2/L3 indexes, the L1 entry VA you can ds_kread64, and the formulas
to convert read entries into next-level table VAs. It does NOT perform live reads;
use the printed `ds_kread64` commands on the device and paste the 64-bit values back
when requested to compute the final L3 PTE VA.
"""
import argparse

def parse_hex(s):
    return int(s, 0)

def fmt(x):
    return f"0x{x:016x}"


def indices_4level(va):
    return ((va >> 39) & 0x1FF, (va >> 30) & 0x1FF, (va >> 21) & 0x1FF, (va >> 12) & 0x1FF)


def indices_3level(va):
    return ((va >> 30) & 0x1FF, (va >> 21) & 0x1FF, (va >> 12) & 0x1FF)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--va', required=True, help='Target virtual address (hex)')
    p.add_argument('--root', required=True, help='Root table virtual address (L0 or L1 base, hex)')
    p.add_argument('--phys2virt', required=False, help='phys_to_virt_offset (hex) if known')
    p.add_argument('--root-level', choices=['0','1'], default='1', help='Root level: 0=L0, 1=L1 (default=1)')
    args = p.parse_args()

    va = parse_hex(args.va)
    root = parse_hex(args.root)
    phys2virt = parse_hex(args.phys2virt) if args.phys2virt else None
    root_level = int(args.root_level)

    print('Target VA:', fmt(va))
    if root_level == 0:
        l0,l1,l2,l3 = indices_4level(va)
        print('Indexes: L0={}, L1={}, L2={}, L3={}'.format(l0,l1,l2,l3))
        l0_entry = root + (l0 * 8)
        print('\nL0 entry VA ->', fmt(l0_entry))
        print('Run on device:')
        print('  ds_kread64', fmt(l0_entry))
        print('\nAfter reading L0_entry (value = VAL_L0):')
        print('  L1_table_va = (VAL_L0 & ~0xfff) + phys_to_virt_offset')
        print('  L1_entry_va  = L1_table_va + (L1_index * 8)')
        print('  ds_kread64 <L1_entry_va>')
        print('\nRepeat for L2 -> L3 to obtain the final L3 PTE:')
        print('  L2_table_va = (VAL_L1 & ~0xfff) + phys_to_virt_offset')
        print('  L2_entry_va = L2_table_va + (L2_index * 8)')
        print('  ds_kread64 <L2_entry_va>')
        print('  L3_table_va = (VAL_L2 & ~0xfff) + phys_to_virt_offset')
        print('  L3_entry_va = L3_table_va + (L3_index * 8)')
        print('  ds_kread64 <L3_entry_va>  # this is the L3 PTE')
    else:
        l1,l2,l3 = indices_3level(va)
        print('Indexes: L1={}, L2={}, L3={}'.format(l1,l2,l3))
        l1_entry = root + (l1 * 8)
        print('\nL1 entry VA ->', fmt(l1_entry))
        print('Run on device:')
        print('  ds_kread64', fmt(l1_entry))
        print('\nAfter reading L1_entry (value = VAL_L1):')
        print('  L2_table_va = (VAL_L1 & ~0xfff) + phys_to_virt_offset')
        print('  L2_entry_va  = L2_table_va + (L2_index * 8)  # L2_index =', l2)
        print('  ds_kread64 <L2_entry_va>')
        print('\nAfter reading L2_entry (value = VAL_L2):')
        print('  L3_table_va = (VAL_L2 & ~0xfff) + phys_to_virt_offset')
        print('  L3_entry_va = L3_table_va + (L3_index * 8)  # L3_index =', l3)
        print('  ds_kread64 <L3_entry_va>  # this is the L3 PTE')

    if phys2virt:
        print('\nphys_to_virt_offset provided:', fmt(phys2virt))
    else:
        print('\nNo phys_to_virt_offset provided — replace with your device-specific value when computing table VAs.')

if __name__ == '__main__':
    main()
