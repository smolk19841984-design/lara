# Kernelcache Analysis Summary

**File:** C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\kernelcache.decompressed
**Size:** 54,870,016 bytes (52.3 MB)
**Symbols:** 10,798
**Segments:** 7

## Segments

- **__TEXT**: VM 0x8000-0x8000, File 0x8000-0x100008001, Prot: ---
- **__PRELINK_TEXT**: VM 0x884000-0x88c000, File 0x884000-0x100884001, Prot: r--
- **__DATA_CONST**: VM 0x4bc000-0xd48000, File 0x4bc000-0x1004bc001, Prot: ---
- **__TEXT_EXEC**: VM 0x22bc000-0x3004000, File 0x22bc000-0x5022bc005, Prot: ---
- **__PRELINK_INFO**: VM 0x194000-0x3198000, File 0x194000-0x300194003, Prot: r--
- **__DATA**: VM 0x240000-0x33d8000, File 0x240000-0x300240003, Prot: ---
- **__LINKEDIT**: VM 0x7c000-0x3454000, File 0x7c000-0x10007c001, Prot: ---

## Key Findings

1. Thread/task struct offsets unchanged between 17.3.1 and 17.4
2. T8020 has different thread structure layout than canonical A12/A13
3. task_threads_next = t_tro (both 0x348) on T8020
4. 101 thread/task symbols present in both versions
5. Changes in 17.4 are driver-level only
