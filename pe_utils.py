import ctypes
import os
import struct
import sys


def read_chunk(filename: str, nbytes: int, endian: str="little"):
    chunk = b""
    current_pos = 0
    with open(filename, "rb") as fh:
        chunk = fh.read(nbytes)
        fh.seek(nbytes)
        current_pos = fh.tell()
    return hex(int.from_bytes(chunk, byteorder=endian)), current_pos


class PEStruct:

    COFF_HDR_STRUCT = struct.Struct("L2H3L2H")
    COFF_FIELD_STRUCT = struct.Struct("H2B6L")
    WIN_FIELD_STRUCT = struct.Struct("3L6H4L2H6L")
    DATA_DIRECTORIES = struct.Struct("32L")
    SECTION_TABLE_STRUCT = struct.Struct("Q6L2HL")


class PEFile(PEStruct):

    def __init__(self, filename, byteorder="little"):
        self.byteorder = byteorder
        self._filename = filename
        self.data = self.read_file()
        self.dos_hdr = self.get_dos_hdr()
        self.sig_offset = self.get_sig_offset()
        self.coff_hdr = self.get_coff_hdr()
        self.coff_fields = self.get_coff_fields()
        self.win_fields = self.get_win_fields()
        self.data_dirs = self.get_data_directories()
        self.section_table = self.get_section_table()

    def read_file(self):
        data = None
        with open(self._filename, "rb") as fh:
            data = fh.read()
        return data

    def get_dos_hdr(self):
        dos_hdr = struct.unpack("H", self.data[0:2])[0]
        return hex(dos_hdr)

    def get_sig_offset(self):
        sig_offset = struct.unpack("L", self.data[int(0x3c):int(0x3c)+4])[0]
        return hex(sig_offset)

    def get_coff_hdr(self):
        coff_hdr = {}
        offset = int(self.sig_offset, 16)
        coff_data = self.COFF_HDR_STRUCT.unpack(self.data[offset:offset+int(self.COFF_HDR_STRUCT.size)])
        coff_hdr["signature"] = hex(coff_data[0])
        coff_hdr["machine"] = f"{self.get_machine_type(hex(coff_data[1]))}: {hex(coff_data[1])}"
        coff_hdr["num_sections"] = int(hex(coff_data[2]), 16)
        coff_hdr["timestamp"] = int(hex(coff_data[3]), 16)
        coff_hdr["symbol_table_ptr"] = hex(coff_data[4])
        coff_hdr["num_symbol_tables"] = int(hex(coff_data[5]), 16)
        coff_hdr["optional_hdr_size"] = hex(coff_data[6])
        coff_hdr["characteristics"] = f"{str(self.get_characteristics(hex(coff_data[7])))}: {hex(coff_data[7])}"
        return coff_hdr

    def get_machine_type(self, hex_id: str):
        n = int(hex_id, 16)
        res = None
        machine_types = {
            "unknown": 0x0,
            "matsushita_am33": 0x1d3,
            "amd64": 0x8664,
            "arm_le": 0x1c0,
            "arm64_le": 0xaa64,
            "armnt_thumb2_le": 0x1c4,
            "ebc_efi_byte_code": 0xebc,
            "i386_intel": 0x14c,
            "ia64_intel_itanium": 0x200,
            "loongarch32": 0x6232,
            "loongarch64": 0x6264,
            "m32r_mitsubishi_le": 0x9041,
            "mips16": 0x266,
            "mips_fpu": 0x366,
            "mips16_fpu": 0x466,
            "powerpc_le": 0x1f0,
            "powerpc_floating_point": 0x1f1,
            "r4000_mips_le": 0x166,
            "riscv32": 0x5032,
            "riscv64": 0x5064,
            "riscv128": 0x5128,
            "sh3_hitachi": 0x1a2,
            "sh3dsp_hitachi": 0x1a3,
            "sh4_hitachi": 0x1a6,
            "sh5_hitachi": 0x1a8,
            "thumb": 0x1c2,
            "mips_le_wce_v2": 0x169
        }
        for k, v in machine_types.items():
            if n == v:
                res = k
                break
        return res

    def get_coff_fields(self):
        coff_fields = {}
        offset = int(self.sig_offset, 16) + self.COFF_HDR_STRUCT.size
        coff_data = self.COFF_FIELD_STRUCT.unpack(self.data[offset:offset+self.COFF_FIELD_STRUCT.size])
        coff_fields["magic"] = f"{self.magic_number(hex(coff_data[0]))}: {hex(coff_data[0])}"
        coff_fields["maj_linker_ver"] = hex(coff_data[1])
        coff_fields["min_linker_ver"] = hex(coff_data[2])
        coff_fields["code_size"] = int(hex(coff_data[3]), 16)
        coff_fields["init_data_size"] = int(hex(coff_data[4]), 16)
        coff_fields["uninit_data_size"] = int(hex(coff_data[5]), 16)
        coff_fields["entry_point_addr"] = hex(coff_data[6])
        coff_fields["code_base_addr"] = hex(coff_data[7])
        coff_fields["data_base_addr"] = hex(coff_data[8])
        return coff_fields

    def magic_number(self, hexstr: str):
        res = None
        n = int(hexstr, 16)
        magic_nums = {
            "PE32": 0x10b,
            "PE32+": 0x20b
        }
        for k, v in magic_nums.items():
            if n == v:
                res = k
                break
        return res

    def get_win_fields(self):
        win_fields = {}
        offset = int(self.sig_offset, 16) + self.COFF_HDR_STRUCT.size + self.COFF_FIELD_STRUCT.size
        win_data = self.WIN_FIELD_STRUCT.unpack(self.data[offset:offset+self.WIN_FIELD_STRUCT.size])
        win_fields["image_base"] = hex(win_data[0])
        win_fields["section_alignment"] = hex(win_data[1])
        win_fields["file_alignment"] = hex(win_data[2])
        win_fields["maj_os_ver"] = hex(win_data[3])
        win_fields["min_os_ver"] = hex(win_data[4])
        win_fields["maj_image_ver"] = hex(win_data[5])
        win_fields["min_image_ver"] = hex(win_data[6])
        win_fields["maj_subsystem_ver"] = hex(win_data[7])
        win_fields["min_subsystem_ver"] = hex(win_data[8])
        win_fields["win32_ver"] = int(hex(win_data[9]), 16)
        win_fields["image_size"] = int(hex(win_data[10]), 16)
        win_fields["header_size"] = int(hex(win_data[11]), 16)
        win_fields["checksum"] = hex(win_data[12])
        win_fields["subsystem"] = hex(win_data[13])
        win_fields["dll_characteristics"] = hex(win_data[14])
        win_fields["stack_size_reserve"] = int(hex(win_data[15]), 16)
        win_fields["stack_size_commit"] = int(hex(win_data[16]), 16)
        win_fields["heap_size_reserve"] = int(hex(win_data[17]), 16)
        win_fields["heap_size_commit"] = int(hex(win_data[18]), 16)
        win_fields["loader_flags"] = hex(win_data[19])
        win_fields["num_rva_and_sizes"] = int(hex(win_data[20]), 16)
        return win_fields

    def get_data_directories(self):
        data_dir = {}
        offset = int(self.sig_offset, 16) + self.COFF_HDR_STRUCT.size + self.COFF_FIELD_STRUCT.size + self.WIN_FIELD_STRUCT.size
        data = self.DATA_DIRECTORIES.unpack(self.data[offset:offset+self.DATA_DIRECTORIES.size])
        data_dir["export_table"] = hex(data[0])
        data_dir["export_table_size"] = int(hex(data[1]), 16)
        data_dir["import_table"] = hex(data[2])
        data_dir["import_table_size"] = int(hex(data[3]), 16)
        data_dir["resource_table"] = hex(data[4])
        data_dir["resource_table_size"] = int(hex(data[5]), 16)
        data_dir["exception_table"] = hex(data[6])
        data_dir["exception_table_size"] = int(hex(data[7]), 16)
        data_dir["certificate_table"] = hex(data[8])
        data_dir["certificate_table_size"] = int(hex(data[9]), 16)
        data_dir["base_reloc_table"] = hex(data[10])
        data_dir["base_reloc_table_size"] = int(hex(data[11]), 16)
        data_dir["debug"] = hex(data[12])
        data_dir["debug_size"] = int(hex(data[13]), 16)
        data_dir["arch_data"] = hex(data[14])
        data_dir["arch_data_size"] = int(hex(data[15]), 16)
        data_dir["global_ptr"] = hex(data[16])
        data_dir["zeroes0"] = hex(data[17])
        data_dir["tls_table"] = hex(data[18])
        data_dir["tls_table_size"] = int(hex(data[19]), 16)
        data_dir["load_config_table"] = hex(data[20])
        data_dir["load_config_table_size"] = int(hex(data[21]), 16)
        data_dir["bound_import"] = hex(data[22])
        data_dir["bound_import_size"] = int(hex(data[23]), 16)
        data_dir["import_addr_table"] = hex(data[24])
        data_dir["import_addr_table_size"] = int(hex(data[25]), 16)
        data_dir["delay_import_descriptor"] = hex(data[26])
        data_dir["delay_import_descriptor_size"] = int(hex(data[27]), 16)
        data_dir["clr_runtime_header"] = hex(data[28])
        data_dir["clr_runtime_header_size"] = int(hex(data[29]), 16)
        data_dir["zeroes1"] = hex(data[30])
        data_dir["zeroes2"] = hex(data[31])
        return data_dir

    def get_section_table(self):
        section_table = {}
        offset = int(self.sig_offset, 16) + self.COFF_HDR_STRUCT.size + self.COFF_FIELD_STRUCT.size + self.DATA_DIRECTORIES.size
        data = self.SECTION_TABLE_STRUCT.unpack(self.data[offset:offset+self.SECTION_TABLE_STRUCT.size])
        section_table["name"] = hex(data[0])
        section_table["virtual_size"] = int(hex(data[1]), 16)
        section_table["virtual_addr"] = hex(data[2])
        section_table["raw_data_size"] = int(hex(data[3]), 16)
        section_table["raw_data_ptr"] = hex(data[4])
        section_table["relocations_ptr"] = hex(data[5])
        section_table["line_numbers_ptr"] = hex(data[6])
        section_table["num_relocations"] = int(hex(data[7]), 16)
        section_table["num_line_numbers"] = int(hex(data[8]), 16)
        section_table["characteristics"] = hex(data[9])
        return section_table

    def get_characteristics(self, hexstr: str):
        chars = []
        n = int(hexstr, 16)
        char_dict = {
            "IMAGE_FILE_RELOCS_STRIPPED": 0x0001,
            "IMAGE_FILE_EXECUTABLE_IMAGE": 0x0002,
            "IMAGE_FILE_LINE_NUMS_STRIPPED": 0x0004,
            "IMAGE_FILE_LOCAL_SYMS_STRIPPED": 0x0008,
            "IMAGE_FILE_AGGRESSIVE_WS_TRIM": 0x0010,
            "IMAGE_FILE_LARGE_ADDRESS_AWARE": 0x0020,
            "RESERVED0": 0x0040,
            "IMAGE_FILE_BYTES_REVERSED_LO": 0x0080,
            "IMAGE_FILE_32BIT_MACHINE": 0x0100,
            "IMAGE_FILE_DEBUG_STRIPPED": 0x0200,
            "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP": 0x0400,
            "IMAGE_FILE_NET_RUN_FROM_SWAP": 0x0800,
            "IMAGE_FILE_SYSTEM": 0x1000,
            "IMAGE_FILE_DLL": 0x2000,
            "IMAGE_FILE_UP_SYSTEM_ONLY": 0x4000,
            "IMAGE_FILE_BYTES_REVERSED_HI": 0x8000
        }
        for i in range(1, 5):
            mask = int("0x{}".format("f"*i), 16)
            j = (i * 4) - 4
            x = ((n & mask) >> j) << j
            for k, v in char_dict.items():
                if x == v:
                    chars.append(k)
                    break
        return chars

