#!/usr/bin/python2
# encoding:utf-8
__author__ = 'ling'

import vstruct
from vstruct import *
from vstruct.primitives import *
from zio import *
import logging

logging.basicConfig(level=logging.DEBUG)
g_logger = logging.getLogger("ELFfile")
g_logger.setLevel(logging.DEBUG)

PT_LOOS = 0x60000000  # OS-specific

# PHDR types
PHDR_TYPE = v_enum()
PHDR_TYPE.PT_NULL = 0
PHDR_TYPE.PT_LOAD = 1
PHDR_TYPE.PT_DYNAMIC = 2
PHDR_TYPE.PT_INTERP = 3
PHDR_TYPE.PT_NOTE = 4
PHDR_TYPE.PT_SHLIB = 5
PHDR_TYPE.PT_PHDR = 6
PHDR_TYPE.PT_TLS = 7  # Thread local storage segment
PHDR_TYPE.PT_LOOS = 0x60000000  # OS-specific
PHDR_TYPE.PT_HIOS = 0x6fffffff  # OS-specific
PHDR_TYPE.PT_LOPROC = 0x70000000
PHDR_TYPE.PT_HIPROC = 0x7fffffff
PHDR_TYPE.PT_GNU_EH_FRAME = 0x6474e550
PHDR_TYPE.PT_GNU_STACK = (PT_LOOS + 0x474e551)
PHDR_TYPE.GNU_RELRO = 0x6474e552

# PHDR flags
PHDR_FLAGS = v_enum()
PHDR_FLAGS.R = 0x4
PHDR_FLAGS.W = 0x2
PHDR_FLAGS.X = 0x1
PHDR_FLAGS.WX = 0x3
PHDR_FLAGS.RX = 0x5
PHDR_FLAGS.RW = 0x6
PHDR_FLAGS.RWX = 0x7

SHDR_TYPE = v_enum()
SHDR_TYPE.SHT_NULL = 0  # sh_type
SHDR_TYPE.SHT_PROGBITS = 1
SHDR_TYPE.SHT_SYMTAB = 2
SHDR_TYPE.SHT_STRTAB = 3
SHDR_TYPE.SHT_RELA = 4
SHDR_TYPE.SHT_HASH = 5
SHDR_TYPE.SHT_DYNAMIC = 6
SHDR_TYPE.SHT_NOTE = 7
SHDR_TYPE.SHT_NOBITS = 8
SHDR_TYPE.SHT_REL = 9
SHDR_TYPE.SHT_SHLIB = 10
SHDR_TYPE.SHT_DYNSYM = 11
SHDR_TYPE.SHT_UNKNOWN12 = 12
SHDR_TYPE.SHT_UNKNOWN13 = 13
SHDR_TYPE.SHT_INIT_ARRAY = 14
SHDR_TYPE.SHT_FINI_ARRAY = 15
SHDR_TYPE.SHT_PREINIT_ARRAY = 16
SHDR_TYPE.SHT_GROUP = 17
SHDR_TYPE.SHT_SYMTAB_SHNDX = 18
SHDR_TYPE.SHT_NUM = 19

DYN_TAG = v_enum()
DYN_TAG.DT_NULL = 0
DYN_TAG.DT_NEEDED = 1
DYN_TAG.DT_PLTRELSZ = 2  # 对应.rel.plt的size
DYN_TAG.DT_PLTGOT = 3  # 对应.plt.got节
DYN_TAG.DT_HASH = 4
DYN_TAG.DT_STRTAB = 5  # 对应.dynstr
DYN_TAG.DT_SYMTAB = 6  # 对应.dynsym
DYN_TAG.DT_RELA = 7
DYN_TAG.DT_RELASZ = 8
DYN_TAG.DT_RELAENT = 9
DYN_TAG.DT_STRSZ = 10  # .dynstr整个节的大小
DYN_TAG.DT_SYMENT = 11  # 每一项符号表的大小
DYN_TAG.DT_INIT = 12
DYN_TAG.DT_FINI = 13
DYN_TAG.DT_SONAME = 14
DYN_TAG.DT_RPATH = 15
DYN_TAG.DT_SYMBOLIC = 16
DYN_TAG.DT_REL = 17  # 对应.rel.dyn节，对数据引用的修正
DYN_TAG.DT_RELSZ = 18  # 对应 .rel.dyn节的大小
DYN_TAG.DT_RELENT = 19
DYN_TAG.DT_PLTREL = 20  # rel type,包括REL和RELA
DYN_TAG.DT_DEBUG = 21
DYN_TAG.DT_TEXTREL = 22
DYN_TAG.DT_JMPREL = 23  # 对应.rel.plt节，对函数引用的修正

DYN_TAG.DT_INIT_ARRAY = 0x19
DYN_TAG.DT_FINI_ARRAY = 0x1a
DYN_TAG.DT_INIT_ARRAYSZ = 0x1b
DYN_TAG.DT_FINI_ARRAYSZ = 0x1c

DYN_TAG.DT_PREINIT_ARRAY = 0x20
DYN_TAG.DT_PREINIT_ARRAYSZ = 0x21

DYN_TAG.DT_VERSYM = 0x6ffffff0
DYN_TAG.DT_VERNEED = 0x6ffffffe
DYN_TAG.DT_VERNEEDNUM = 0x6fffffff
DYN_TAG.DT_LOPROC = 0x70000000
DYN_TAG.DT_HIPROC = 0x7fffffffD

ST_BIND = v_enum()
ST_BIND.STB_LOCAL = 0
ST_BIND.STB_GLOBAL = 1
ST_BIND.STB_WEAK = 2
ST_BIND.STB_LOPROC = 13
ST_BIND.STB_HIPROC = 15

ST_TYPE = v_enum()
ST_TYPE.STT_NOTYPE = 0
ST_TYPE.STT_OBJECT = 1
ST_TYPE.STT_FUNC = 2
ST_TYPE.STT_SECTION = 3
ST_TYPE.STT_FILE = 4
ST_TYPE.STT_LOPROC = 13
ST_TYPE.STT_HIPROC = 15

PLTREL_TYPE = v_enum()
PLTREL_TYPE.REL = 0x11
PLTREL_TYPE.RELA = 0x7

ST_NDX = v_enum()
ST_NDX.SHN_UNDEF = 0
ST_NDX.SHN_LORESERVE = 0xff00
ST_NDX.SHN_LOPROC = 0xff00
ST_NDX.SHN_HIPROC = 0xff1f
ST_NDX.SHN_ABS = 0xfff1  # The symbol has an absolute value that will not change because of relocation.
ST_NDX.SHN_COMMON = 0xfff2  # The symbol labels a common block that has not yet been allocated.
ST_NDX.SHN_HIRESERVE = 0xffff

R_TYPE = v_enum()
R_TYPE.R_386_NONE = 0
R_TYPE.R_386_32 = 1
R_TYPE.R_386_PC32 = 2
R_TYPE.R_386_GOT32 = 3
R_TYPE.R_386_PLT32 = 4
R_TYPE.R_386_COPY = 5
R_TYPE.R_386_GLOB_DAT = 6
R_TYPE.R_386_JMP_SLOT = 7
R_TYPE.R_386_RELATIVE = 8
R_TYPE.R_386_GOTOFF = 9
R_TYPE.R_386_GOTPC = 10

R_TYPE64 = v_enum()
R_TYPE64.R_X86_64_NONE = 0  # No reloc
R_TYPE64.R_X86_64_64 = 1  # Direct 64 bit
R_TYPE64.R_X86_64_PC32 = 2  # PC relative 32 bit signed
R_TYPE64.R_X86_64_GOT32 = 3  # 32 bit GOT entry
R_TYPE64.R_X86_64_PLT32 = 4  # 32 bit PLT address
R_TYPE64.R_X86_64_COPY = 5  # Copy symbol at runtime
R_TYPE64.R_X86_64_GLOB_DAT = 6  # Create GOT entry
R_TYPE64.R_X86_64_JUMP_SLOT = 7  # Create PLT entry
R_TYPE64.R_X86_64_RELATIVE = 8  # Adjust by program base
R_TYPE64.R_X86_64_GOTPCREL = 9  # 32 bit signed pc relative offset to GOT
R_TYPE64.R_X86_64_32 = 10  # Direct 32 bit zero extended
R_TYPE64.R_X86_64_32S = 11  # Direct 32 bit sign extended
R_TYPE64.R_X86_64_16 = 12  # Direct 16 bit zero extended
R_TYPE64.R_X86_64_PC16 = 13  # 16 bit sign extended pc relative
R_TYPE64.R_X86_64_8 = 14  # Direct 8 bit sign extended
R_TYPE64.R_X86_64_PC8 = 15  # 8 bit sign extended pc relative
R_TYPE64.R_X86_64_NUM = 16


class ElfEhdr(vstruct.VStruct):
    def __init__(self, bits=32):
        super(ElfEhdr, self).__init__()
        self.e_ident = v_bytes(16)  # ident bytes
        self.e_type = v_uint16()  # file type
        self.e_machine = v_uint16()  # target machine
        self.e_version = v_uint32()  # file version
        if bits == 32:
            self.e_entry = v_uint32()  # start address
            self.e_phoff = v_uint32()  # phdr file offset
            self.e_shoff = v_uint32()  # shdr file offset
        else:
            self.e_entry = v_uint64()
            self.e_phoff = v_uint64()
            self.e_shoff = v_uint64()
        self.e_flags = v_uint32()  # file flags
        self.e_ehsize = v_uint16()  # sizeof ehdr
        self.e_phentsize = v_uint16()  # sizeof phdr
        self.e_phnum = v_uint16()  # number phdrs
        self.e_shentsize = v_uint16()  # sizeof shdr
        self.e_shnum = v_uint16()  # number shdrs
        self.e_shstrndx = v_uint16()  # shdr string index


class ElfPhdr(vstruct.VStruct):
    def __init__(self, bits=32):
        super(ElfPhdr, self).__init__()
        if bits == 32:
            self.p_type = v_uint32(enum=PHDR_TYPE)  # entry type
            self.p_offset = v_uint32()  # file offset
            self.p_vaddr = v_uint32()  # virtual address
            self.p_paddr = v_uint32()  # physical address
            self.p_filesz = v_uint32()  # file size
            self.p_memsz = v_uint32()  # memory size
            self.p_flags = v_uint32(enum=PHDR_FLAGS)  # entry flags
            self.p_align = v_uint32()  # memory/file alignment
        else:
            self.p_type = v_uint32(enum=PHDR_TYPE)  # entry type
            self.p_flags = v_uint32(enum=PHDR_FLAGS)  # entry flags
            self.p_offset = v_uint64()  # file offset
            self.p_vaddr = v_uint64()  # virtual address
            self.p_paddr = v_uint64()  # physical address
            self.p_filesz = v_uint64()  # file size
            self.p_memsz = v_uint64()  # memory size
            self.p_align = v_uint64()  # memory/file alignment


class ElfPhdrArray(vstruct.VArray):
    def __init__(self, number=0, bits=32):
        super(ElfPhdrArray, self).__init__()
        self.number = number
        self.bits = bits

    def vsSetNumber(self, number):
        self.number = number

    def vsParse(self, sbytes, offset=0):
        for i in range(self.number):
            elf_phdr = ElfPhdr(bits=self.bits)
            offset = elf_phdr.vsParse(sbytes, offset=offset)
            self.vsAddElement(elf_phdr)
        return offset


class ElfShdr(vstruct.VStruct):
    def __init__(self, bits=32):
        super(ElfShdr, self).__init__()
        if bits == 32:
            self.sh_name = v_uint32()  # section name
            self.sh_type = v_uint32(enum=SHDR_TYPE)  # SHT_...
            self.sh_flags = v_uint32()  # SHF_...
            self.sh_addr = v_uint32()  # virtual address
            self.sh_offset = v_uint32()  # file offset
            self.sh_size = v_uint32()  # section size
            self.sh_link = v_uint32()  # misc info
            self.sh_info = v_uint32()  # misc info
            self.sh_addralign = v_uint32()  # memory alignment
            self.sh_entsize = v_uint32()  # entry size if table
        else:
            self.sh_name = v_uint32()  # section name
            self.sh_type = v_uint32(enum=SHDR_TYPE)  # SHT_...
            self.sh_flags = v_uint64()  # SHF_...
            self.sh_addr = v_uint64()  # virtual address
            self.sh_offset = v_uint64()  # file offset
            self.sh_size = v_uint64()  # section size
            self.sh_link = v_uint32()  # misc info
            self.sh_info = v_uint32()  # misc info
            self.sh_addralign = v_uint64()  # memory alignment
            self.sh_entsize = v_uint64()  # entry size if table


class ElfShdrArray(vstruct.VArray):
    def __init__(self, number=0, bits=32):
        super(ElfShdrArray, self).__init__()
        self.number = number
        self.bits = bits

    def vsSetNumber(self, number):
        self.number = number

    def vsParse(self, sbytes, offset=0):
        for i in range(self.number):
            elf_shdr = ElfShdr(bits=self.bits)
            offset = elf_shdr.vsParse(sbytes, offset=offset)
            self.vsAddElement(elf_shdr)
        return offset


class ElfDyn(vstruct.VStruct):
    def __init__(self, bits=32):
        super(ElfDyn, self).__init__()
        if bits == 32:
            self.d_tag = v_uint32(enum=DYN_TAG)
            self.d_val = v_uint32()
        else:
            self.d_tag = v_uint64(enum=DYN_TAG)
            self.d_val = v_uint64()


class ElfDynArray(vstruct.VArray):
    def __init__(self, max_number=0, bits=32):
        super(ElfDynArray, self).__init__()
        self.max_number = max_number
        self.bits = bits
        self.number = 0
        self.offset = 0  # 动态节表在文件中的偏移。

    def set_max_number(self, max_number):
        self.max_number = max_number

    def vsParse(self, sbytes, offset=0):
        self.offset = offset
        for i in range(self.max_number):
            elf_dyn = ElfDyn(bits=self.bits)
            offset = elf_dyn.vsParse(sbytes, offset=offset)
            if (elf_dyn.d_tag == 0) & (elf_dyn.d_val == 0):
                self.vsAddElement(elf_dyn)
                self.number += 1
                break
            self.vsAddElement(elf_dyn)
            self.number += 1
        return offset


# the low 4 bit is the type; the high 4 bit is the bind
class ElfStInfo(vstruct.VStruct):
    def __init__(self, bits=32):
        super(ElfStInfo, self).__init__()
        self.st_bind = v_uint8(enum=ST_BIND)
        self.st_type = v_uint8(enum=ST_TYPE)
        self.bit = bits

    def vsParse(self, bytez, offset=0):
        value = l8(bytez[offset])
        self.st_bind = (value >> 4) & 0xf
        self.st_type = value & 0xf
        return offset + 1


class ElfSym(vstruct.VStruct):
    def __init__(self, bits=32):
        super(ElfSym, self).__init__()
        if bits == 32:
            self.st_name = v_uint32()
            self.st_value = v_uint32()
            self.st_size = v_uint32()
            self.st_info = ElfStInfo()  # 8 bit
            self.st_other = v_uint8()
            self.st_shndx = v_uint16(enum=ST_NDX)
        else:
            self.st_name = v_uint32()
            self.st_info = ElfStInfo()  # 8 bit
            self.st_other = v_uint8()
            self.st_shndx = v_uint16(enum=ST_NDX)
            self.st_value = v_uint64()
            self.st_size = v_uint64()


class ElfSymArray(vstruct.VArray):
    def __init__(self, number=0, bits=32):
        super(ElfSymArray, self).__init__()
        self.number = number
        self.bits = bits

    def vsSetNumber(self, number):
        self.number = number

    def vsParse(self, sbytes, offset=0):
        for i in range(self.number):
            elf_sym = ElfSym(bits=self.bits)
            offset = elf_sym.vsParse(sbytes, offset=offset)
            self.vsAddElement(elf_sym)
        return offset


class ElfRInfo(vstruct.VStruct):
    def __init__(self, bits=32):
        super(ElfRInfo, self).__init__()
        self.r_sym = v_uint32()
        if bits == 32:
            self.r_type = v_uint8(enum=R_TYPE)
        else:
            self.r_type = v_uint8(enum=R_TYPE64)
        self.bits = bits

    def vsParse(self, bytez, offset=0):
        if self.bits == 32:
            value = l32(bytez[offset:offset + 4])
            self.r_sym = value >> 8
            self.r_type = value & 0xff
            return offset + 4
        else:
            value = l64(bytez[offset:offset + 8])
            self.r_sym = value >> 32
            self.r_type = value & 0xffffffff
            return offset + 8


class ElfRel(vstruct.VStruct):
    def __init__(self, bits=32):
        super(ElfRel, self).__init__()
        if bits == 32:
            self.r_offset = v_uint32()
            self.r_info = ElfRInfo(bits=bits)  # 32 bit
        else:
            self.r_offset = v_uint64()
            self.r_info = ElfRInfo(bits=bits)  # 64 bit


class ElfRela(vstruct.VStruct):
    def __init__(self, bits=32):
        super(ElfRela, self).__init__()
        if bits == 32:
            self.r_offset = v_uint32()
            self.r_info = ElfRInfo(bits=bits)  # 32 bit
            self.r_append = v_uint32()
        else:
            self.r_offset = v_uint64()
            self.r_info = ElfRInfo(bits=bits)  # 64 bit
            self.r_append = v_uint64()


class ElfRelArray(vstruct.VArray):
    # type = 0, rel;  type=1, rela
    def __init__(self, number=0, bits=32, rel_type=0):
        super(ElfRelArray, self).__init__()
        self.number = number
        self.bits = bits
        self.rel_type = rel_type

    def vsSetReltype(self, rel_type):
        self.rel_type = rel_type

    def vsSetNumber(self, number):
        self.number = number

    def vsParse(self, sbytes, offset=0):
        for i in range(self.number):
            if self.rel_type == 0:
                elf_rel = ElfRel(bits=self.bits)
            else:
                elf_rel = ElfRela(bits=self.bits)
            offset = elf_rel.vsParse(sbytes, offset=offset)
            self.vsAddElement(elf_rel)
        return offset


class Elf():
    def get_bits(self, data):
        ei_class = l8(data[4])
        if ei_class == 1:
            return 32
        elif ei_class == 2:
            return 64
        else:
            raise Exception('not known bits')

    def generate_dynamic_infos(self):
        dynamic_infos = {}
        for i, elf_dyn in self.elf_dyns:
            d_tag = elf_dyn._vs_values.get('d_tag')
            if isinstance(d_tag, vs_prims.v_number):
                if d_tag.vsGetEnum() is not None:
                    dynamic_infos[str(d_tag)[3:]] = elf_dyn.d_val

        # print dynamic_infos
        return dynamic_infos

    def parse_elf(self, data):

        self.elf_ehdr.vsParse(data)

        self.elf_phdrs.vsSetNumber(self.elf_ehdr.e_phnum)
        self.elf_phdrs.vsParse(data, self.elf_ehdr.e_phoff)

        self.elf_shdrs.vsSetNumber(self.elf_ehdr.e_shnum)
        self.elf_shdrs.vsParse(data, self.elf_ehdr.e_shoff)

        self.dynamic_infos = None
        for i, elf_phdr in self.elf_phdrs:
            # p_type = elf_phdr._vs_values.get('p_type')

            if elf_phdr.p_type == PHDR_TYPE.PT_DYNAMIC:
                # print elf_phdr.p_offset, elf_phdr.p_filesz
                self.elf_dyns.set_max_number(elf_phdr.p_filesz / (self.bits / 4))
                self.elf_dyns.vsParse(data, elf_phdr.p_offset)

                self.dynamic_infos = self.generate_dynamic_infos()

        if self.dynamic_infos is None:
            raise Exception('not find dynamic program header')

        # .dyn.sym
        if ('SYMTAB' in self.dynamic_infos.keys()) & ('STRTAB' in self.dynamic_infos.keys()) & \
                ('SYMENT' in self.dynamic_infos.keys()):
            self.symtab = self.vma2offset(self.dynamic_infos['SYMTAB'])
            self.strtab = self.vma2offset(self.dynamic_infos['STRTAB'])
            syment = self.dynamic_infos['SYMENT']

            # it's not a good way, I will modify this later
            symsize = self.strtab - self.symtab

            self.elf_syms.vsSetNumber(symsize / syment)
            self.elf_syms.vsParse(data, self.symtab)

        # .rel.dyn
        if 'PLTREL' in self.dynamic_infos.keys():
            if self.dynamic_infos['PLTREL'] == PLTREL_TYPE.REL:
                self.rel_type = 0
            elif self.dynamic_infos['PLTREL'] == PLTREL_TYPE.RELA:
                self.rel_type = 1
            else:
                raise Exception('not known rel type:%x' % self.dynamic_infos['PLTREL'])

        if self.rel_type == 0:
            if ('REL' in self.dynamic_infos.keys()) & ('RELSZ' in self.dynamic_infos.keys()) \
                    & ('RELENT' in self.dynamic_infos.keys()):
                rel_offset = self.vma2offset(self.dynamic_infos['REL'])
                rel_size = self.dynamic_infos['RELSZ']
                rel_ent = self.dynamic_infos['RELENT']

                self.dyn_syms.vsSetNumber(rel_size / rel_ent)
                self.dyn_syms.vsSetReltype(self.rel_type)
                self.dyn_syms.vsParse(data, rel_offset)

        if self.rel_type == 1:
            if ('RELA' in self.dynamic_infos.keys()) & ('RELASZ' in self.dynamic_infos.keys()) \
                    & ('RELAENT' in self.dynamic_infos.keys()):
                rel_offset = self.vma2offset(self.dynamic_infos['RELA'])
                rel_size = self.dynamic_infos['RELASZ']
                rel_ent = self.dynamic_infos['RELAENT']

                self.dyn_syms.vsSetNumber(rel_size / rel_ent)
                self.dyn_syms.vsSetReltype(self.rel_type)
                self.dyn_syms.vsParse(data, rel_offset)

        # .rel.plt
        if ('JMPREL' in self.dynamic_infos.keys()) & ('PLTRELSZ' in self.dynamic_infos.keys()):
            rel_offset = self.vma2offset(self.dynamic_infos['JMPREL'])
            rel_size = self.dynamic_infos['PLTRELSZ']
            if 'RELAENT' in self.dynamic_infos.keys():
                rel_ent = self.dynamic_infos['RELAENT']
            elif 'RELENT' in self.dynamic_infos.keys():
                rel_ent = self.dynamic_infos['RELENT']

            self.plt_syms.vsSetNumber(rel_size / rel_ent)
            self.plt_syms.vsSetReltype(self.rel_type)
            self.plt_syms.vsParse(data, rel_offset)

    def get_name(self, offset):
        return self.data[offset:].split('\x00')[0]

    def generate_symbol(self):
        symbol = {}
        for i, elf_sym in self.elf_syms:
            name = self.get_name(self.strtab + elf_sym.st_name)
            if name == '':
                continue
            if elf_sym.st_value == 0:
                continue
            symbol[name] = elf_sym.st_value
        return symbol

    def generate_got_and_plt(self):
        got = {}
        for i, plt_sym in self.plt_syms:
            name = self.get_name(self.strtab + self.elf_syms[plt_sym.r_info.r_sym].st_name)
            got[name] = plt_sym.r_offset
        plt = {}
        for k, v in got.items():
            offset = self.vma2offset(v)
            plt[k] = l32(self.data[offset:offset + 4]) - 6
        return got, plt

    def offset2vma(self, offset):
        for i, elf_phdr in self.elf_phdrs:
            if elf_phdr.p_type != PHDR_TYPE.PT_LOAD:
                continue
            if (offset > elf_phdr.p_offset) & (offset < (elf_phdr.p_offset + elf_phdr.p_filesz)):
                return offset - elf_phdr.p_offset + elf_phdr.p_vaddr
        return -1

    def vma2offset(self, vma):
        for i, elf_phdr in self.elf_phdrs:
            if elf_phdr.p_type != PHDR_TYPE.PT_LOAD:
                continue
            if (vma > elf_phdr.p_vaddr) & (vma < (elf_phdr.p_vaddr + elf_phdr.p_filesz)):
                return vma - elf_phdr.p_vaddr + elf_phdr.p_offset
        return -1

    def get_code(self):
        for i, elf_phdr in self.elf_phdrs:
            if elf_phdr.p_type != PHDR_TYPE.PT_LOAD:
                continue
            if elf_phdr.p_offset == 0:
                return self.data[0:elf_phdr.p_filesz]
        return None

    # 返回给定字符串的虚拟地址。
    def find_str(self, string):
        index = self.data.find(string)
        return self.offset2vma(index)

    def print_elf_info(self):
        print 'elf_ehdr:'
        print self.elf_ehdr.tree()
        print 'elf_phdrs:'
        print self.elf_phdrs.tree()
        print 'elf_shdrs:'
        print self.elf_shdrs.tree()
        print 'elf_dyns:'
        print self.elf_dyns.tree()

        print 'elf_syms:'
        print self.elf_syms.tree()
        print 'dyn_dyns:'
        print self.dyn_syms.tree()
        print 'plt_syms:'
        print self.plt_syms.tree()

    def __init__(self, elf_file):
        f = open(elf_file, 'rb')
        self.data = f.read()
        f.close()

        # 32 or 64
        self.bits = self.get_bits(self.data)

        self.elf_ehdr = ElfEhdr(bits=self.bits)
        self.elf_phdrs = ElfPhdrArray(bits=self.bits)

        self.elf_shdrs = ElfShdrArray(bits=self.bits)

        self.elf_dyns = ElfDynArray(bits=self.bits)
        self.dynamic_infos = {}

        # .dyn.sym
        self.elf_syms = ElfSymArray(bits=self.bits)

        # .rel.dyn
        self.dyn_syms = ElfRelArray(bits=self.bits)
        self.rel_type = 0

        self.strtab = 0

        # .rel.plt
        self.plt_syms = ElfRelArray(bits=self.bits)

        self.parse_elf(self.data)

        # self.print_elf_info()

        self.plt = {}
        self.got = {}
        self.got, self.plt = self.generate_got_and_plt()

        self.symbol = {}
        self.symbol = self.generate_symbol()

'''
if __name__ == '__main__':
    elf = Elf('./test/libc-2.19.so')
    print elf.symbol
'''
