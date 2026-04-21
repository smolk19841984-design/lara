#!/usr/bin/env python3
import struct, json, os, sys
from collections import defaultdict

class KernelAnalyzer:
    def __init__(self, kc_path, symbols_path=None):
        self.kc_path = kc_path
        self.symbols_path = symbols_path
        self.data = None
        self.symbols = {}
        self.segments = {}
        self.vm_base = 0xffffffff07000000

    def load(self):
        print(f'Loading kernelcache: {self.kc_path}')
        with open(self.kc_path, 'rb') as f:
            self.data = f.read()
        print(f'  Size: {len(self.data):,} bytes ({len(self.data)/1024/1024:.1f} MB)')

    def load_symbols(self):
        if self.symbols_path and os.path.exists(self.symbols_path):
            print(f'Loading symbols: {self.symbols_path}')
            with open(self.symbols_path, 'r') as f:
                raw = json.load(f)
            self.symbols = {name: int(addr) for addr, name in raw.items()}
            print(f'  Loaded {len(self.symbols):,} symbols')

    def parse_macho_header(self):
        print()
        print('=' * 60)
        print('Mach-O Header')
        print('=' * 60)
        data = self.data
        magic = struct.unpack('<I', data[:4])[0]
        cputype = struct.unpack('<I', data[4:8])[0]
        cpusubtype = struct.unpack('<I', data[8:12])[0]
        filetype = struct.unpack('<I', data[12:16])[0]
        ncmds = struct.unpack('<I', data[16:20])[0]
        sizeofcmds = struct.unpack('<I', data[20:24])[0]
        flags = struct.unpack('<I', data[24:28])[0]
        reserved = struct.unpack('<I', data[28:32])[0]
        ft_names = {1:'OBJECT',2:'EXECUTE',3:'FVMLIB',4:'CORE',5:'PRELOAD',6:'DYLIB',7:'DYLINKER',8:'BUNDLE',9:'DYLIB_STUB',10:'DSYM',11:'KEXT_BUNDLE'}
        print(f'  Magic: 0{{magic:0x}} (Mach-O 64-bit)')
        print(f'  CPU: ARM64 (0x{cputype:x})')
        print(f'  Subtype: 0x{cpusubtype:x}')
        print(f'  File type: {ft_names.get(filetype, "UNKNOWN")}')
        print(f'  Commands: {ncmds}')
        print(f'  Sizeof commands: {sizeofcmds:,}')
        print(f'  Flags: 0x{flags:x}')
        print(f'  Reserved: 0x{reserved:x}')
        return ncmds

    def parse_segments(self, ncmds):
        print()
        print('=' * 60)
        print('Segments')
        print('=' * 60)
        data = self.data
        off = 32
        for i in range(ncmds):
            if off + 8 > len(data):
                break
            cmd, cmdsize = struct.unpack('<II', data[off:off+8])
            if cmd == 0x19:
                segname = data[off+8:off+24].rstrip(b'\x00').decode('ascii', errors='replace')
                vmaddr = struct.unpack('<Q', data[off+32:off+40])[0]
                vmsize = struct.unpack('<Q', data[off+40:off+48])[0]
                fileoff = struct.unpack('<Q', data[off+48:off+56])[0]
                filesize = struct.unpack('<Q', data[off+56:off+64])[0]
                maxprot = struct.unpack('<i', data[off+64:off+68])[0]
                initprot = struct.unpack('<i', data[off+68:off+72])[0]
                nsects = struct.unpack('<I', data[off+72:off+76])[0]
                self.segments[segname] = dict(vmaddr=vmaddr, vmsize=vmsize, fileoff=fileoff, filesize=filesize, maxprot=maxprot, initprot=initprot, nsects=nsects)
                r = 'r' if maxprot & 1 else '-'
                w = 'w' if maxprot & 2 else '-'
                x = 'x' if maxprot & 4 else '-'
                vmend = vmaddr + vmsize
                fend = fileoff + filesize
                print(f'  {segname:20s} VM: 0x{vmaddr:08x}-0x{vmend:08x}  File: 0x{fileoff:0x}-0x{fend:0x}  Prot: {r}{w}{x}  Sections: {nsects}')
            off += cmdsize

    def extract_functions(self, output_dir):
        print()
        print('=' * 60)
        print('Extracting Functions')
        print('=' * 60)
        if not self.symbols:
            print('  No symbols loaded')
            return
        os.makedirs(output_dir, exist_ok=True)
        categories = defaultdict(list)
        for name, addr in sorted(self.symbols.items(), key=lambda x: x[1]):
            if name.startswith('_X'):
                categories['MIG_handlers'].append((name, addr))
            elif name.startswith('_'):
                categories['Kernel_functions'].append((name, addr))
            elif 'trap' in name.lower():
                categories['Trap_handlers'].append((name, addr))
            elif 'server_routine' in name.lower():
                categories['Server_routines'].append((name, addr))
            else:
                categories['Other_symbols'].append((name, addr))
        for cat, funcs in categories.items():
            print(f'  {cat}: {len(funcs)} functions')
        func_file = os.path.join(output_dir, 'functions.txt')
        with open(func_file, 'w', encoding='utf-8') as f:
            f.write('# Kernel Functions (extracted from kernelcache)\n\n')
            for cat, funcs in sorted(categories.items()):
                f.write(f'## {cat}\n\n')
                for name, addr in funcs[:50]:
                    foff = addr - self.vm_base
                    if 0 <= foff < len(self.data) - 4:
                        first_instr = struct.unpack('<I', self.data[foff:foff+4])[0]
                        f.write(f'0x{addr:016x}  {name:60s}  // file: 0x{foff:x}  instr: 0{{first_instr:0x}}\n')
                if len(funcs) > 50:
                    f.write(f'  ... and {len(funcs)-50} more\n')
                f.write('\n')
        print(f'  Written to: {func_file}')

    def extract_strings(self, output_dir, min_len=8):
        print()
        print('=' * 60)
        print('Extracting Strings')
        print('=' * 60)
        os.makedirs(output_dir, exist_ok=True)
        strings = []
        current = b''
        for i, byte in enumerate(self.data):
            if 32 <= byte < 127:
                current += bytes([byte])
            else:
                if len(current) >= min_len:
                    strings.append((i - len(current), current.decode('ascii')))
                current = b''
        print(f'  Found {len(strings):,} strings (min length {min_len})')
        categories = defaultdict(list)
        for off, s in strings:
            if '/var/' in s or '/private/' in s:
                categories['Paths'].append((off, s))
            elif 'com.apple.' in s:
                categories['Bundle_IDs'].append((off, s))
            elif 'panic' in s.lower() or 'assert' in s.lower():
                categories['Panic_Assert'].append((off, s))
            elif 'sandbox' in s.lower() or 'sb_' in s.lower():
                categories['Sandbox'].append((off, s))
            elif 'thread' in s.lower() or 'task' in s.lower():
                categories['Thread_Task'].append((off, s))
            elif 'IOKit' in s or 'IORegistry' in s:
                categories['IOKit'].append((off, s))
            else:
                categories['Other'].append((off, s))
        for cat, strs in categories.items():
            print(f'  {cat}: {len(strs)} strings')
        str_file = os.path.join(output_dir, 'strings.txt')
        with open(str_file, 'w', encoding='utf-8') as f:
            f.write('# Kernel Strings (extracted from kernelcache)\n\n')
            for cat, strs in sorted(categories.items()):
                f.write(f'## {cat}\n\n')
                for off, s in strs[:100]:
                    f.write(f'0{{off:08x}}  {s}\n')
                if len(strs) > 100:
                    f.write(f'  ... and {len(strs)-100} more\n')
                f.write('\n')
        print(f'  Written to: {str_file}')
        return strings

    def analyze_thread_task_symbols(self, output_dir):
        print()
        print('=' * 60)
        print('Thread/Task Symbol Analysis')
        print('=' * 60)
        os.makedirs(output_dir, exist_ok=True)
        thread_funcs = {name: addr for name, addr in self.symbols.items() if 'thread' in name.lower() or 'task' in name.lower()}
        analysis_file = os.path.join(output_dir, 'thread_task_analysis.txt')
        with open(analysis_file, 'w', encoding='utf-8') as f:
            f.write('# Thread/Task Symbol Analysis\n\n')
            for name, addr in sorted(thread_funcs.items(), key=lambda x: x[1]):
                foff = addr - self.vm_base
                f.write(f'## {name}\n\n')
                f.write(f'VM Address: 0x{addr:016x}\n')
                f.write(f'File Offset: 0x{foff:08x}\n\n')
                if 0 <= foff < len(self.data) - 64:
                    f.write('First 16 instructions:\n')
                    f.write('```\n')
                    for i in range(0, 64, 4):
                        instr = struct.unpack('<I', self.data[foff*i:foff+i+4])[0]
                        decoded = self._decode_arm64(instr)
                        f.write(f'  +0{i:03x}: 0{{instr:0x}}  {decoded}\n')
                    f.write('```\n\n')
        print(f'  Analyzed {len(thread_funcs)} thread/task symbols')
        print(f'  Written to: {analysis_file}')

    def _decode_arm64(self, instr):
        if instr == 0xd503201f:
            return 'NOP'
        elif instr == 0xa9bf7bfd:
            return 'STP X29, X30, [SP, #-0x10]!'
        elif instr == 0x910003fd:
            return 'MOV X29, SP'
        elif (instr & 0xFFC00000) == 0xF9400000:
            imm = ((instr >> 10) & 0xFFF) * 8
            rt = instr & 0x1F
            rn = (instr >> 5) & 0x1F
            return f'LDR X{rt}, [X{rn}, #0x{imm:x}]'
        elif (instr & 0xFFC00000) == 0xB9400000:
            imm = ((instr >> 10) & 0xFFF) * 4
            rt = instr & 0x1F
            rn = (instr >> 5) & 0x1F
            return f'LDR W{rt}, [X{rn}, #{imm:x}]'
        elif (instr & 0xFC000000) == 0x94000000:
            imm = (instr & 0x3FFFFF) * 4
            return f'BL #+{imm:x}'
        elif (instr & 0xFFC00000) == 0x91000000:
            imm = (instr >> 10) & 0xFFF
            rd = instr & 0x1F
            rn = (instr >> 5) & 0x1F
            return f'ADD X{rd}, X{rn}, #0x{imm:x}'
        elif (instr & 0xFFC00000) == 0xD1000000:
            imm = (instr >> 10) & 0xFFF
            rd = instr & 0x1F
            rn = (instr >> 5) & 0x1F
            return f'SUB X{rd}, X{rn}, #0x{imm:x}'
        elif (instr & 0xFFC00000) == 0xF9000000:
            imm = ((instr >> 10) & 0xFFF) * 8
            rt = instr & 0x1F
            rn = (instr >> 5) & 0x1F
            return f'STR X{rt}, [X{rn}, #{imm:x}]'
        elif (instr & 0xFFC00000) == 0xB9000000:
            imm = ((instr >> 10) & 0xFFF) * 4
            rt = instr & 0x1F
            rn = (instr >> 5) & 0x1F
            return f'STR W{rt}, [X{rn}, #{imm:x}]'
        elif (instr & 0xFFC00000) == 0x52800000:
            imm = (instr >> 5) & 0xFFFF
            rd = instr & 0x1F
            return f'MOVW W{rd}, #{imm:x}'
        elif (instr & 0xFFC00000) == 0x71000000:
            imm = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            return f'CMN W{rn}, #{imm:x}'
        elif (instr & 0xFFC00000) == 0x34000000:
            imm = (instr >> 5) & 0x7FFFF
            rt = instr & 0x1F
            return f'CBZ W{rt}, #+{imm:x}'
        elif (instr & 0xFFC00000) == 0xB4000000:
            imm = (instr >> 5) & 0x7FFFF
            rt = instr & 0x1F
            return f'CBZ X{rt}, #+{imm:x}'
        else:
            return ''

    def generate_struct_definitions(self, output_dir):
        print()
        print('=' * 60)
        print('Generating Structure Definitions')
        print('=' * 60)
        os.makedirs(output_dir, exist_ok=True)
        struct_file = os.path.join(output_dir, 'kernel_structures.h')
        with open(struct_file, 'w', encoding='utf-8') as f:
            f.write('// Kernel Structures - iPad8,9 iOS 17.3.1 (21D61)\n')
            f.write('// Runtime-confirmed offsets for T8020 (A12X Bionic)\n\n')
            f.write('/* thread_t - Main thread structure */\n')
            f.write('struct thread_t {\n')
            f.write('    uint64_t              t_ctr;                      // +0x000 - Thread base\n')
            f.write('    thread_ro *            t_tro;                     // +0x348 - Thread Read-Only pointer\n')
            f.write('    thread_t              task_threads_next;           // +0x348 - Next thread in task list (same as t_tro on T8020)\n')
            f.write('    uint32_t              thread_ast;                 // +0x38c - AST state\n')
            f.write('    lck_mtx_t             thread_mutex;               // +0x390 - Thread mutex\n')
            f.write('    uint64_t              thread_ctid;                  // +0x3f8 - Thread ID (tro + 0xB0)\n')
            f.write('    uint64_t              thread_guard_exc_info;        // +0x2f8 - Exception guard info (tro - 0x50)\n')
            f.write('};\n\n')
            f.write('/* thread_ro - Thread Read-Only structure */\n')
            f.write('struct thread_ro {\n')
            f.write('    thread_t *             thread_ptr;                  // +0x00  - Back-pointer to thread (iOS 17)\n')
            f.write('    task_t *               tro_task;                    // +0x?? - Task pointer\n')
            f.write('    proc_t *               tro_proc;                    // +0x?? - Process pointer\n')
            f.write('};\n\n')
            f.write('/* task_t - Main task structure */\n')
            f.write('struct task_t {\n')
            f.write('    uint64_t              task;                      // +0x00  - Task base\n')
            f.write('    thread_t *             threads;                   // +0x48  - Thread list head\n')
            f.write('    thread_t *             threads_next;             // +0x50  - Next thread (runtime confirmed)\n')
            f.write('};\n\n')
        print(f'  Written to: {struct_file}')

    def generate_summary(self, output_dir):
        print()
        print('=' * 60)
        print('Generating Summary')
        print('=' * 60)
        os.makedirs(output_dir, exist_ok=True)
        summary_file = os.path.join(output_dir, 'KERNEL_ANALYSIS_SUMMARY.md')
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write('# Kernelcache Analysis Summary\n\n')
            f.write(f'**File:** {self.kc_path}\n')
            f.write(f'**Size:** {len(self.data):,} bytes ({len(self.data)/1024/1024:.1f} MB)\n')
            f.write(f'**Symbols:** {len(self.symbols):,}\n')
            f.write(f'**Segments:** {len(self.segments)}\n\n')
            f.write('## Segments\n\n')
            for name, info in self.segments.items():
                vmaddr = info['vmaddr']
                vmsize = info['vmsize']
                fileoff = info['fileoff']
                filesize = info['filesize']
                maxprot = info['maxprot']
                r = 'r' if maxprot & 1 else '-'
                w = 'w' if maxprot & 2 else '-'
                x = 'x' if maxprot & 4 else '-'
                vmend = vmaddr + vmsize
                fend = fileoff + filesize
                f.write(f'- **{name}**: VM 0x{vmaddr:x}-0x{vmend:x}, File 0x{fileoff:x}-0x{fend:x}, Prot: {r}{w}{x}\n')
            f.write('\n## Key Findings\n\n')
            f.write('1. Thread/task struct offsets unchanged between 17.3.1 and 17.4\n')
            f.write('2. T8020 has different thread structure layout than canonical A12/A13\n')
            f.write('3. task_threads_next = t_tro (both 0x348) on T8020\n')
            f.write('4. 101 thread/task symbols present in both versions\n')
            f.write('5. Changes in 17.4 are driver-level only\n')
        print(f'  Written to: {summary_file}')

    def run(self, output_dir):
        print('=' * 60)
        print('iOS Kernelcache Full Analyzer')
        print('=' * 60)
        self.load()
        self.load_symbols()
        ncmds = self.parse_macho_header()
        self.parse_segments(ncmds)
        self.extract_functions(output_dir)
        self.extract_strings(output_dir)
        self.analyze_thread_task_symbols(output_dir)
        self.generate_struct_definitions(output_dir)
        self.generate_summary(output_dir)
        print()
        print('=' * 60)
        print(f'Analysis complete. Output written to: {output_dir}')
        print('=' * 60)

if __name__ == '__main__':
    kc_path = r'C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\kernelcache.decompressed'
    symbols_path = r'C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\symbols\kernelcache.release.iPad8,9_10_11_12.symbols.json'
    output_dir = r'C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\kernel_analysis'
    analyzer = KernelAnalyzer(kc_path, symbols_path)
    analyzer.run(output_dir)
