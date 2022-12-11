from pe_base.pe_base import PEBase


class COFFHeader(PEBase):

    @property
    def size(self):
        return self.COFF_HDR_STRUCT.size

    @property
    def get_sig_offset(self):
        return self.sig_offset

    def get_coff_hdr(self):
        coff_hdr = {}
        offset = int(self.sig_offset, 16)
        coff_data = self.COFF_HDR_STRUCT.unpack(self.data[offset:offset+int(self.COFF_HDR_STRUCT.size)])
        coff_hdr["signature"] = hex(coff_data[0])
        coff_hdr["machine"] = f"{self.get_machine_type(hex(coff_data[1]))}: {hex(coff_data[1])}"
        coff_hdr["number_of_sections"] = int(hex(coff_data[2]), 16)
        coff_hdr["time_date_stamp"] = int(hex(coff_data[3]), 16)
        coff_hdr["ptr_to_symbol_table"] = hex(coff_data[4])
        coff_hdr["number_of_symbol_tables"] = int(hex(coff_data[5]), 16)
        coff_hdr["sizeof_optional_hdr"] = hex(coff_data[6])
        coff_hdr["characteristics"] = f"{str(self.get_characteristics(hex(coff_data[7])))}: {hex(coff_data[7])}"
        return coff_hdr

    def get_machine_type(self, hexstr: str):
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
        res = self.hexstr2val(hexstr, machine_types)
        return res

    def get_characteristics(self, hexstr: str):
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
        res = self.hexstr2arr(hexstr, char_dict)
        return res
