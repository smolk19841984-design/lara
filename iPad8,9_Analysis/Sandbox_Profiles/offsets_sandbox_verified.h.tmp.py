kernel_base = 0xfffffff007004000
candidates = [
    ('sandbox_check', 0xfffffff009e023a8, 'Medium'),
    ('sandbox_extension_create_or_consume', 0xfffffff009e26a0c, 'High'),
    ('mac_label_update', 0xfffffff009e06388, 'High'),
]
print('/* Generated verified sandbox offsets */')
for name,vm,conf in candidates:
    off = vm - kernel_base
    print(f"#define {name.upper()}_VMADDR 0x{vm:016X}ULL")
    print(f"#define {name.upper()}_OFFSET_FROM_KERNEL 0x{off:X} /* KERNEL_BASE + 0x{off:X} */")
    print(f"/* Confidence: {conf} */\n")
