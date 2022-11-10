import struct

from models.pe_base import PEBase


class WindowsFields(PEBase):

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

    def get_win_subsystem(self, hexstr: str):
        res = None
        n = int(hexstr, 16)
        subsys_dict = {
            "IMAGE_SUBSYSTEM_UNKNOWN": 0,
            "IMAGE_SUBSYSTEM_NATIVE": 1,
            "IMAGE_SUBSYSTEM_WINDOWS_GUI": 2,
            "IMAGE_SUBSYSTEM_WINDOWS_CUI": 3,
            
        }