from pe_base.pe_base import PEBase


class WindowsFields(PEBase):

    def get_win_fields(self):
        win_fields = {}
        bit_size = self.get_arch_type()
        if bit_size == "PE32+":
            WIN_FIELD_STRUCT = self.WIN64_FIELD_STRUCT
            STANDARD_HDR_SIZE = self.COFF64_FIELD_STRUCT.size
        else:
            WIN_FIELD_STRUCT = self.WIN_FIELD_STRUCT
            STANDARD_HDR_SIZE = self.COFF_FIELD_STRUCT.size
        self.WIN_FIELD_STRUCT_SIZE = WIN_FIELD_STRUCT.size
        offset = int(self.sig_offset, 16) + self.COFF_HDR_STRUCT.size + STANDARD_HDR_SIZE
        win_data = WIN_FIELD_STRUCT.unpack(self.data[offset:offset+WIN_FIELD_STRUCT.size])
        win_fields["image_base"] = hex(win_data[0])
        win_fields["section_alignment"] = hex(win_data[1])
        win_fields["file_alignment"] = hex(win_data[2])
        win_fields["maj_os_ver"] = hex(win_data[3])
        win_fields["min_os_ver"] = hex(win_data[4])
        win_fields["maj_image_ver"] = hex(win_data[5])
        win_fields["min_image_ver"] = hex(win_data[6])
        win_fields["maj_subsystem_ver"] = hex(win_data[7])
        win_fields["min_subsystem_ver"] = hex(win_data[8])
        win_fields["win32_ver"] = hex(win_data[9])
        win_fields["image_size"] = hex(win_data[10])
        win_fields["header_size"] = hex(win_data[11])
        win_fields["checksum"] = hex(win_data[12])
        win_fields["subsystem"] = self.get_win_subsystem(hex(win_data[13]))
        win_fields["dll_characteristics"] = f"{self.get_dll_characteristics(hex(win_data[14]))}: {hex(win_data[14])}"
        win_fields["stack_size_reserve"] = hex(win_data[15])
        win_fields["stack_size_commit"] = hex(win_data[16])
        win_fields["heap_size_reserve"] = hex(win_data[17])
        win_fields["heap_size_commit"] = hex(win_data[18])
        win_fields["loader_flags"] = hex(win_data[19])
        win_fields["number_of_rva_and_sizes"] = hex(win_data[20])
        return win_fields

    def get_win_subsystem(self, hexstr: str):
        subsys_dict = {
            "IMAGE_SUBSYSTEM_UNKNOWN": 0,
            "IMAGE_SUBSYSTEM_NATIVE": 1,
            "IMAGE_SUBSYSTEM_WINDOWS_GUI": 2,
            "IMAGE_SUBSYSTEM_WINDOWS_CUI": 3,
            "IMAGE_SUBSYSTEM_OS2_CUI": 5,
            "IMAGE_SUBSYSTEM_POSIX_CUI": 7,
            "IMAGE_SUBSYSTEM_NATIVE_WINDOWS": 8,
            "IMAGE_SUBSYSTEM_WINDOWS_CE_CUI": 9,
            "IMAGE_SUBSYSTEM_EFI_APPLICATION": 10,
            "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER": 11,
            "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER": 12,
            "IMAGE_SUBSYSTEM_EFI_ROM": 13,
            "IMAGE_SUBSYSTEM_EFI_XBOX": 14,
            "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION": 16
        }
        res = self.hexstr2val(hexstr, subsys_dict)
        return res

    def get_dll_characteristics(self, hexstr: str):
        dll_chr_dict = {
            "RESERVED1": 0x0001,
            "RESERVED2": 0x0002,
            "RESERVED3": 0x0004,
            "RESERVED4": 0x0008,
            "IMAGE_DLLCHARATERISTICS_HIGH_ENTROPY_VA": 0x0020,
            "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE": 0x0040,
            "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY": 0x0080,
            "IMAGE_DLLCHARACTERISTICS_NX_COMPAT": 0x0100,
            "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION": 0x0200,
            "IMAGE_DLLCHARACTERISTICS_NO_SEH": 0x0400,
            "IMAGE_DLLCHARACTERISTICS_NO_BIND": 0x0800,
            "IMAGE_DLLCHARACTERISTICS_APPCONTAINER": 0x1000,
            "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER": 0x2000,
            "IMAGE_DLLCHARACTERISTICS_GUARD_CF": 0x4000,
            "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE": 0x8000
        }
        res = self.hexstr2arr(hexstr, dll_chr_dict)
        return res

