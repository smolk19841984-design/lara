#!/usr/bin/env python3
"""
offline_kernel_emu.py

Best-effort offline ARM64 emulator + kernel analyzer for iOS 17.3.1 kernelcache.

Usage:
  python offline_kernel_emu.py --kernel kernelcache.release.ipad8 --base 0xfffffff007004000

Produces: offline_analysis_results.json

Requires: lief, capstone
"""
import sys
import argparse
import json
import struct
from collections import defaultdict

try:
    import lief
    from capstone import *
    from capstone.arm64 import *
except Exception as e:
    print("Missing dependency: please install 'lief' and 'capstone' in your environment")
    raise


class MachOImage:
    def __init__(self, path):
        self.path = path
        self.binary = lief.parse(path)
        self._build_segments()

    def _build_segments(self):
        self.segments = []
        # Each segment: dict with vmaddr, vmsize, file_offset, file_size
        for seg in self.binary.segments:
            vmaddr = getattr(seg, 'virtual_address', None)
            vmsize = getattr(seg, 'virtual_size', None)
            if vmsize is None:
                vmsize = getattr(seg, 'size', None)
            fileoff = getattr(seg, 'file_offset', None)
            if fileoff is None:
                fileoff = getattr(seg, 'offset', None)
            filesize = getattr(seg, 'physical_size', None)
            if filesize is None:
                filesize = getattr(seg, 'file_size', None)
            if filesize is None:
                filesize = vmsize
            self.segments.append({
                'name': getattr(seg, 'name', ''),
                'vmaddr': vmaddr,
                'vmsize': vmsize,
                'fileoff': fileoff,
                'filesize': filesize,
            })

        with open(self.path, 'rb') as f:
            self.data = f.read()

    def va_to_offset(self, va):
        for s in self.segments:
            if s['vmaddr'] <= va < s['vmaddr'] + s['vmsize']:
                return s['fileoff'] + (va - s['vmaddr'])
        return None

    def read_u64(self, va):
        off = self.va_to_offset(va)
        if off is None or off + 8 > len(self.data):
            return None
        return struct.unpack_from('<Q', self.data, off)[0]

    def read_u32(self, va):
        off = self.va_to_offset(va)
        if off is None or off + 4 > len(self.data):
            return None
        return struct.unpack_from('<I', self.data, off)[0]

    def read_u8(self, va):
        off = self.va_to_offset(va)
        if off is None or off + 1 > len(self.data):
            return None
        return self.data[off]

    def get_text_ranges(self):
        ranges = []
        for s in self.segments:
            if s['name'] == '__TEXT' or s['name'] == '__text' or '.text' in s['name']:
                ranges.append((s['vmaddr'], s['vmsize']))
        # fallback: include any executable segment
        if not ranges:
            for s in self.segments:
                ranges.append((s['vmaddr'], s['vmsize']))
                break
        return ranges

    def symbols(self):
        syms = {}
        try:
            for sym in self.binary.symbols:
                name = sym.name
                if name.startswith('_'):
                    name = name[1:]
                syms[name] = sym.value
        except Exception:
            pass
        return syms


class SimpleARM64Emu:
    def __init__(self, image, kernel_base):
        self.image = image
        self.kernel_base = kernel_base
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.cs.detail = True

    def _reg_name(self, reg_id):
        return self.cs.reg_name(reg_id)

    def disasm(self, va, max_insns=200):
        off = self.image.va_to_offset(va)
        if off is None:
            return []
        # read some bytes
        data = self.image.data[off: off + 8 * max_insns]
        return list(self.cs.disasm(data, va))

    # Heuristic: try to find const value assigned to a register by walking backwards
    def find_register_constant_backward(self, all_insns, idx, reg_name, max_back=40):
        # all_insns is list of instructions in order; idx is index of current insn
        val = None
        for i in range(idx - 1, max(idx - max_back - 1, -1), -1):
            insn = all_insns[i]
            mnem = insn.mnemonic
            ops = insn.operands
            # Handle MOVZ/MOVK
            if mnem in ('movz', 'movk'):
                # capstone operand[0] is reg, operand[1] is imm, optional shift
                if len(ops) >= 2 and ops[0].type == ARM64_OP_REG:
                    dst = self._reg_name(ops[0].reg)
                    if dst == reg_name:
                        imm = ops[1].imm if ops[1].type == ARM64_OP_IMM else 0
                        # check for shift (op[2])
                        shift = 0
                        if len(ops) >= 3 and ops[2].type == ARM64_OP_IMM:
                            shift = ops[2].imm
                        if mnem == 'movz':
                            val = (imm << shift)
                        else:  # movk
                            if val is None:
                                val = 0
                            mask = (1 << 16) - 1
                            val = (val & ~(mask << shift)) | (imm << shift)
                        # continue scanning as MOVK may be multiple
            # Handle ADRP + ADD pattern: ADRP sets reg to page, ADD adds immediate
            if mnem == 'adrp' and len(ops) >= 2 and ops[0].type == ARM64_OP_REG:
                dst = self._reg_name(ops[0].reg)
                if dst == reg_name:
                    # operand[1] is imm absolute page computed by capstone
                    if ops[1].type == ARM64_OP_IMM:
                        val = ops[1].imm
            if mnem == 'add' and len(ops) >= 3 and ops[0].type == ARM64_OP_REG:
                dst = self._reg_name(ops[0].reg)
                if dst == reg_name and ops[1].type == ARM64_OP_REG and ops[2].type == ARM64_OP_IMM:
                    base = self._reg_name(ops[1].reg)
                    imm = ops[2].imm
                    if base == 'xzr' or base == 'x0' and val is None:
                        val = imm
                    elif val is not None:
                        val = (val + imm) & 0xffffffffffffffff
            # direct MOV (alias) from immediate not common; LDR literal loads immediate/address
            if mnem.startswith('ldr') and len(ops) >= 2 and ops[0].type == ARM64_OP_REG:
                dst = self._reg_name(ops[0].reg)
                if dst == reg_name:
                    # if operand is MEM with PC relative, capstone gives imm
                    if ops[1].type == ARM64_OP_MEM and ops[1].mem.base == ARM64_REG_PC:
                        # capstone may not expose immediate here; compute from insn imm if present
                        if hasattr(insn, 'operands') and insn.operands[1].type == ARM64_OP_MEM:
                            disp = insn.operands[1].mem.disp
                            # read pointer at (insn.address + disp)
                            ptr_va = insn.address + disp
                            try:
                                val = self.image.read_u64(ptr_va)
                            except Exception:
                                val = None
            if val is not None:
                return val
        return None


def find_proc_offsets(image, emu):
    # Heuristic: scan text for 'str' storing a 32-bit register with small constant to [x0, #off]
    candidates = defaultdict(list)
    text_ranges = image.get_text_ranges()
    for base, size in text_ranges:
        insns = emu.disasm(base, max_insns=20000)
        for idx, insn in enumerate(insns):
            if insn.mnemonic.startswith('str'):
                # check mem operand
                ops = insn.operands
                if len(ops) >= 2 and ops[1].type == ARM64_OP_MEM:
                    base_reg = emu._reg_name(ops[1].mem.base)
                    disp = ops[1].mem.disp
                    if base_reg == 'x0':
                        # determine which register is being stored
                        if ops[0].type == ARM64_OP_REG:
                            src = emu._reg_name(ops[0].reg)
                            # try to resolve constant assigned to src
                            val = emu.find_register_constant_backward(insns, idx, src)
                            if val is not None and (val == 0 or val < 0x10000 or val == 0x1f5):
                                candidates[disp].append((insn.address, src, val))
    # choose offsets with most hits
    ranked = sorted(candidates.items(), key=lambda kv: len(kv[1]), reverse=True)
    result = {}
    if ranked:
        # pick top candidates for uid/gid etc
        # assume first is p_uid, second p_gid, third p_svuid, fourth p_svgid if available
        names = ['p_uid_offset', 'p_gid_offset', 'p_svuid_offset', 'p_svgid_offset']
        for i, (off, hits) in enumerate(ranked[:4]):
            result[names[i]] = hex(off & 0xffffffff)
    return result


def find_amfi_cs_disable(image, emu, symbols):
    # Try to resolve 'amfi' base via symbol table
    amfi_addr = None
    for key in ('amfi', '_amfi', 'g_amfi'):
        if key in symbols:
            amfi_addr = symbols[key]
            break

    # If not found, try to find from symbol 'AMFIInitialize'
    if amfi_addr is None:
        for sym_name in ('AMFIInitialize', '_AMFIInitialize'):
            if sym_name in symbols:
                addr = symbols[sym_name]
                # emulate first instructions to find ADRP+ADD to get amfi base
                insns = emu.disasm(addr, max_insns=200)
                base = None
                for i, insn in enumerate(insns[:40]):
                    if insn.mnemonic == 'adrp' and len(insn.operands) >= 2:
                        dst = emu._reg_name(insn.operands[0].reg)
                        imm = insn.operands[1].imm if insn.operands[1].type == ARM64_OP_IMM else None
                        if imm:
                            # look for subsequent add
                            for j in range(i+1, i+6):
                                if j < len(insns) and insns[j].mnemonic == 'add':
                                    ops = insns[j].operands
                                    if ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_REG and ops[2].type == ARM64_OP_IMM:
                                        base = imm + ops[2].imm
                                        break
                    if base:
                        amfi_addr = base
                        break

    cs_off = None
    if amfi_addr:
        # scan text for LDRB or LDR accessing amfi base
        text_ranges = image.get_text_ranges()
        for base, size in text_ranges:
            insns = emu.disasm(base, max_insns=20000)
            for insn in insns:
                if insn.mnemonic in ('ldrb', 'ldr') and len(insn.operands) >= 1:
                    op = insn.operands[-1]
                    if op.type == ARM64_OP_MEM and op.mem.base != 0:
                        mem_base_name = emu._reg_name(op.mem.base)
                        # if we find ADRP+ADD sequence loading amfi base into a reg, try to detect offset
                        # For simplicity, look for literal memory access where mem.base==PC and points into data near amfi
                        if op.mem.base == ARM64_REG_PC and op.mem.disp:
                            ptr_va = insn.address + op.mem.disp
                            maybe = image.read_u64(ptr_va)
                            if maybe and amfi_addr and abs(maybe - amfi_addr) < 0x2000:
                                cs_off = hex(maybe - amfi_addr)
                                break
                if cs_off:
                    break
            if cs_off:
                break

    return {'base_address_unslid': hex(amfi_addr) if amfi_addr else None, 'cs_enforcement_disable_offset': cs_off}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--kernel', required=True)
    parser.add_argument('--base', default='0xfffffff007004000')
    parser.add_argument('--symbols', required=False, help='Path to symbols JSON file to load exact addresses')
    args = parser.parse_args()

    kernel_path = args.kernel
    kernel_base = int(args.base, 16)

    print('Loading Mach-O image...')
    img = MachOImage(kernel_path)
    symbols = img.symbols()
    # If a symbols JSON file provided, prefer it
    if args.symbols:
        try:
            with open(args.symbols, 'r', encoding='utf-8') as sf:
                j = json.load(sf)
                # determine format: either dict of name->addr or list
                if isinstance(j, dict):
                    # normalize keys: remove leading '_' if present and convert to int
                    parsed = {}
                    for k, v in j.items():
                        name = k.lstrip('_')
                        try:
                            addr = int(v, 16) if isinstance(v, str) and v.startswith('0x') else int(v)
                        except Exception:
                            try:
                                addr = int(str(v), 0)
                            except Exception:
                                continue
                        parsed[name] = addr
                    symbols = parsed
                elif isinstance(j, list):
                    parsed = {}
                    for entry in j:
                        if isinstance(entry, dict) and 'name' in entry and 'address' in entry:
                            name = entry['name'].lstrip('_')
                            try:
                                addr = int(entry['address'], 16) if isinstance(entry['address'], str) and entry['address'].startswith('0x') else int(entry['address'])
                            except Exception:
                                continue
                            parsed[name] = addr
                    symbols = parsed
            print(f'Loaded {len(symbols)} symbols from {args.symbols}')
        except Exception as e:
            print('Failed to load symbols JSON:', e)
    else:
        print(f'Found {len(symbols)} symbols from Mach-O (symbol table may be stripped)')

    emu = SimpleARM64Emu(img, kernel_base)

    print('Analyzing for proc offsets (heuristic)...')
    proc_result = find_proc_offsets(img, emu)

    print('Analyzing for amfi cs_enforcement_disable (heuristic)...')
    amfi_result = find_amfi_cs_disable(img, emu, symbols)

    out = {
        'struct_proc': {
            'p_uid_offset': proc_result.get('p_uid_offset'),
            'p_gid_offset': proc_result.get('p_gid_offset'),
            'p_svuid_offset': proc_result.get('p_svuid_offset'),
            'p_svgid_offset': proc_result.get('p_svgid_offset'),
            'confidence': 'Medium'
        },
        'struct_amfi': {
            'base_address_unslid': amfi_result.get('base_address_unslid'),
            'cs_enforcement_disable_offset': amfi_result.get('cs_enforcement_disable_offset'),
            'confidence': 'Medium'
        },
        'verified_functions': {}
    }

    # Optionally add vn_open/vn_write if present in symbol table
    for fn in ('vn_open', 'vn_write'):
        if fn in symbols:
            out['verified_functions'][fn] = hex(symbols[fn])

    with open('offline_analysis_results.json', 'w') as f:
        json.dump(out, f, indent=2)

    print('Wrote offline_analysis_results.json')

    # If symbol file provided, do targeted disassembly and analysis for requested symbols
    if args.symbols:
        targets = {
            'functions': ['proc_ucred', 'proc_getucred', 'proc_task', 'AMFIInitialize', 'AMFIInit', 'sandbox_check', 'vn_open', 'vn_write', 'vfs_context_current'],
            'globals': ['kernproc', 'amfi', '_amfi', 'rootvnode']
        }
        confirmed = {}
        for fn in targets['functions']:
            if fn in symbols:
                addr = symbols[fn]
                insns = emu.disasm(addr, max_insns=300)
                # collect mem accesses of form ldr/str with reg base likely X0/X1
                found = []
                for insn in insns[:200]:
                    if insn.mnemonic.startswith('ldr') or insn.mnemonic.startswith('str'):
                        for op in insn.operands:
                            if op.type == ARM64_OP_MEM:
                                base = emu._reg_name(op.mem.base)
                                disp = op.mem.disp
                                found.append({'address': hex(insn.address), 'mnemonic': insn.mnemonic, 'base': base, 'disp': hex(disp) if disp is not None else None, 'op_str': insn.op_str})
                confirmed[fn] = {'address': hex(addr), 'disasm_sample': [ {'addr': hex(i.address), 'bytes': i.bytes.hex(), 'text': i.mnemonic + ' ' + i.op_str} for i in insns[:100] ], 'mem_accesses': found}

        # Globals
        globals_found = {}
        for g in targets['globals']:
            if g in symbols:
                globals_found[g] = hex(symbols[g])

        # Update output and write header file
        out['targeted_analysis'] = confirmed
        out['globals'] = globals_found
        with open('offline_analysis_results.json', 'w') as f:
            json.dump(out, f, indent=2)

        # Generate C header with offsets if we detect likely offsets
        header_lines = []
        header_lines.append('/* final_confirmed_offsets.h - generated */')
        header_lines.append('#pragma once')
        # Try to infer p_uid/p_gid from proc_ucred memory accesses where base is x0 and disp small
        puid = None
        pgid = None
        camfi = None
        if 'proc_ucred' in confirmed:
            for acc in confirmed['proc_ucred']['mem_accesses']:
                if acc['base'] in ('x0','x1') and acc['disp'] is not None:
                    disp = int(acc['disp'],16)
                    if puid is None:
                        puid = disp
                    elif pgid is None and disp != puid:
                        pgid = disp
        if 'amfi' in globals_found:
            camfi = int(globals_found['amfi'],16)
        # write defines if found
        if puid is not None:
            header_lines.append(f'#define P_UID_OFFSET 0x{puid:x}')
        if pgid is not None:
            header_lines.append(f'#define P_GID_OFFSET 0x{pgid:x}')
        if camfi is not None:
            header_lines.append(f'#define AMFI_BASE 0x{camfi:x}')

        with open('final_confirmed_offsets.h', 'w') as hf:
            hf.write('\n'.join(header_lines) + '\n')

        print('Wrote updated offline_analysis_results.json and final_confirmed_offsets.h')


if __name__ == '__main__':
    main()
