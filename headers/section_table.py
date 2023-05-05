from models.pe_base import PEBase

import struct
import ctypes
from typing import NamedTuple


class SectionTable(PEBase):

    """
    The number of table entries in the section table is show in the COFF Header number_of_sections field.
    Each table entry has a size of 40 bytes. The format is shown in the get_section_table method.
    """

    SECTION_NAMES = []

    def get_section_table(self, offset: int):
        section_table = {}
        data = self.SECTION_TABLE_STRUCT.unpack(self.data[offset:offset+self.SECTION_TABLE_STRUCT.size])
        sect_name = self.decode_name(hex(data[0]))
        if sect_name not in self.SECTION_NAMES:
            self.SECTION_NAMES.append(sect_name)
        section_table["name"] = f"{sect_name}: {hex(data[0])}"
        section_table["virtual_size"] = int(hex(data[1]), 16)
        section_table["virtual_addr"] = hex(data[2])
        section_table["sizeof_raw_data"] = hex(data[3])
        section_table["ptr_to_raw_data"] = hex(data[4])
        section_table["ptr_to_relocations"] = hex(data[5])
        section_table["ptr_to_line_numbers"] = hex(data[6])
        section_table["number_of_relocations"] = int(hex(data[7]), 16)
        section_table["number_of_line_numbers"] = int(hex(data[8]), 16)
        section_table["characteristics"] = f"{self.get_characteristic_flags(hex(data[9]))}: {hex(data[9])}"
        return section_table

    def get_characteristic_flags(self, hexstr: str):
        char_flags_dict = {
            #"RESERVED1": 0x00000000,
            #"RESERVED2": 0x00000001,
            #"RESERVED3": 0x00000002,
            #"RESERVED4": 0x00000004,
            "IMAGE_SCN_TYPE_NO_PAD": 0x00000008,
            #"RESERVED5": 0x00000010,
            "IMAGE_SCN_CNT_CODE": 0x00000020,
            "IMAGE_SCN_CNT_INITIALIZED_DATA": 0x00000040,
            "IMAGE_SCN_CNT_UNINITIALIZED_DATA": 0x00000080,
            "IMAGE_SCN_LNK_OTHER": 0x00000100,
            "IMAGE_SCN_LNK_INFO": 0x00000200,
            #"RESERVED6": 0x00000400,
            "IMAGE_SCN_LNK_REMOVE": 0x00000800,
            "IMAGE_SCN_LNK_COMDAT": 0x00001000,
            "IMAGE_SCN_GPREL": 0x00008000,
            "IMAGE_SCN_MEM_PURGEABLE": 0x00010000,
            "IMAGE_SCN_MEM_16BIT": 0x00020000,
            "IMAGE_SCN_MEM_LOCKED": 0x00040000,
            "IMAGE_SCN_MEM_PRELOAD": 0x00080000,
            "IMAGE_SCN_ALIGN_1BYTES": 0x00100000,
            "IMAGE_SCN_ALIGN_2BYTES": 0x00200000,
            "IMAGE_SCN_ALIGN_4BYTES": 0x00300000,
            "IMAGE_SCN_ALIGN_8BYTES": 0x00400000,
            "IMAGE_SCN_ALIGN_16BYTES": 0x00500000,
            "IMAGE_SCN_ALIGN_32BYTES": 0x00600000,
            "IMAGE_SCN_ALIGN_64BYTES": 0x00700000,
            "IMAGE_SCN_ALIGN_128BYTES": 0x00800000,
            "IMAGE_SCN_ALIGN_256BYTES": 0x00900000,
            "IMAGE_SCN_ALIGN_512BYTES": 0x00A00000,
            "IMAGE_SCN_ALIGN_1024BYTES": 0x00B00000,
            "IMAGE_SCN_ALIGN_2048BYTES": 0x00C00000,
            "IMAGE_SCN_ALIGN_4096BYTES": 0x00D00000,
            "IMAGE_SCN_ALIGN_8192BYTES": 0x00E00000,
            "IMAGE_SCN_LNK_NRELOC_OVFL": 0x01000000,
            "IMAGE_SCN_MEM_DISCARDABLE": 0x02000000,
            "IMAGE_SCN_MEM_NOT_CACHED": 0x04000000,
            "IMAGE_SCN_MEM_NOT_PAGED": 0x08000000,
            "IMAGE_SCN_MEM_SHARED": 0x10000000,
            "IMAGE_SCN_MEM_EXECUTE": 0x20000000,
            "IMAGE_SCN_MEM_READ": 0x40000000,
            "IMAGE_SCN_MEM_WRITE": 0x80000000
        }
        res = self.hexstr2arr(hexstr, char_flags_dict, nsize=8)
        return res

    def decode_name(self, hexstr: str):
        res = ""
        hexstr = hexstr[2:]
        for i in range(0, len(hexstr), 2):
            c = "0x{}{}".format(hexstr[i], hexstr[i+1])
            c = chr(int(c, 16))
            res = str(c) + res
        return res

    def get_sections(self, num_sections: int, section_offset: int):
        section_dict = {}
        for i in range(0, num_sections):
            offset = (i * 40) + section_offset
            sec = self.get_section_table(offset)
            section_dict[str(i+1)] = sec
        return section_dict


class RelocRecord(NamedTuple):

    VirtualAddress: str
    SymbolTableIndex: str
    Type: str


class COFFRelocations:

    def __init__(self, sectable_dict: dict, raw_data):
        self.section_table = sectable_dict
        self.raw_data = raw_data
        self.RELOC_STRUCT = struct.Struct("2LH")

    def get_sect_reloc(self, sec_num: int):
        reloc_dict = {}
        sect_dict = self.section_table[str(sec_num)]
        num_relocs = sect_dict["number_of_relocations"]
        if int(num_relocs) == 0:
            return None
        reloc_ptr = int(sect_dict["ptr_to_relocations"], 16)
        for i in range(1, int(num_relocs)+1):
            reloc_rec = RelocRecord()
            reloc_end = int(i * self.RELOC_STRUCT.size) + reloc_ptr
            reloc_raw_data = self.raw_data[reloc_ptr:reloc_end]
            reloc_data = self.RELOC_STRUCT.unpack(reloc_raw_data)
            reloc_rec.VirtualAddress = hex(reloc_data[0])
            reloc_rec.SymbolTableIndex = hex(reloc_data[1])
            reloc_rec.Type = hex(reloc_data[2])
            reloc_dict[str(i)] = reloc_rec
        return reloc_dict

    def get_type64(self, hexstr: str):
        res = None
        n = int(hexstr, 16)
        type_dict = {
            "IMAGE_REL_AMD64_ABSOLUTE": 0x0000,
            "IMAGE_REL_AMD64_ADDR64": 0x0001,
            "IMAGE_REL_AMD64_ADDR32": 0x0002,
            "IMAGE_REL_AMD64_ADDR32NB": 0x0003,
            "IMAGE_REL_AMD64_REL32": 0x0004,
            "IMAGE_REL_AMD64_REL32_1": 0x0005,
            "IMAGE_REL_AMD64_REL32_2": 0x0006,
            "IMAGE_REL_AMD64_REL32_3": 0x0007,
            "IMAGE_REL_AMD64_REL32_4": 0x0008,
            "IMAGE_REL_AMD64_REL32_5": 0x0009,
            "IMAGE_REL_AMD64_SECTION": 0X000A,
            "IMAGE_REL_AMD64_SECREL": 0x000B,
            "IMAGE_REL_AMD64_SECREL7": 0x000C,
            "IMAGE_REL_AMD64_TOKEN": 0x000D,
            "IMAGE_REL_AMD64_SREL32": 0x000E,
            "IMAGE_REL_AMD64_PAIR": 0x000F,
            "IMAGE_REL_AMD64_SSPAN32": 0x0010
        }
        for k, v in type_dict.items():
            if n == v:
                res = k
                break
        return res

    def get_type_arm(self, hexstr: str):
        res = None
        n = int(hexstr, 16)
        type_dict = {
            "IMAGE_REL_ARM_ABSOLUTE": 0x0000,
            "IMAGE_REL_ARM_ADDR32": 0x0001,
            "IMAGE_REL_ARM_ADDR32NB": 0x0002,
            "IMAGE_REL_ARM_BRANCH24": 0x0003,
            "IMAGE_REL_ARM_BRANCH11": 0x0004,
            "IMAGE_REL_ARM_REL32": 0x000A,
            "IMAGE_REL_ARM_SECTION": 0x000E,
            "IMAGE_REL_ARM_SECREL": 0x000F,
            "IMAGE_REL_ARM_MOV32": 0x0010,
            "IMAGE_REL_THUMB_MOV32": 0x0011,
            "IMAGE_REL_THUMB_BRANCH20": 0x0012,
            "IMAGE_REL_THUMB_BRANCH24": 0x0014,
            "IMAGE_REL_THUMB_BLX23": 0x0015,
            "IMAGE_REL_ARM_PAIR": 0x0016
        }
        for k, v in type_dict.items():
            if n == v:
                res = k
                break
        return res