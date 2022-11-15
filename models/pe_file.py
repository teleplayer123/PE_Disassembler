from headers.optional_hdrs.data_directories import DataDirectories
from headers.optional_hdrs.standard_fields import StandardFields
from headers.optional_hdrs.windows_fields import WindowsFields
from headers.coff_hdr import COFFHeader
from headers.section_table import SectionTable
from tools.hexdump import xdump


class PEFile:

    def __init__(self, filename: str, byteorder: str="little"):
        self.data = self.read_file(filename)
        self.coff_hdr_obj = COFFHeader(filename, byteorder=byteorder)
        self.coff_hdr = self.coff_hdr_obj.get_coff_hdr()
        self.standard_fields_obj = StandardFields(filename, byteorder=byteorder)
        self.standard_fields = self.standard_fields_obj.get_standard_fields()
        self.win_fields_obj = WindowsFields(filename, byteorder=byteorder)
        self.win_fields = self.win_fields_obj.get_win_fields()
        self.data_dir_obj = DataDirectories(filename, byteorder=byteorder)
        self.data_directories = self.data_dir_obj.get_data_directories()
        sig_offset = int(self.coff_hdr_obj.get_sig_offset, 16)
        self.sect_offset = sig_offset + self.coff_hdr_obj.size + self.sizeof_opt_hdr
        self.section_table_obj = SectionTable(filename, byteorder=byteorder)
        self.section_table = self.section_table_obj.get_section_table(self.sect_offset)


    def read_file(self, filename):
        data = None
        with open(filename, "rb") as fh:
            data = fh.read()
        return data

    def get_section_table_entry(self, offset: int):
        entry = self.section_table_obj.get_section_table(offset)
        return entry

    def dump_section(self, data, offset: int, sec_size: int=40):
        try:
            chunk = data[offset:offset+sec_size]
            return xdump(chunk)
        except IndexError:
            print("Data not available at offset {}".format(offset))
            return

    @property
    def num_of_sections(self):
        num_of_sections = self.coff_hdr["number_of_sections"]
        return num_of_sections

    @property
    def sizeof_opt_hdr(self):
        sizeof_opt_hdr = self.coff_hdr["sizeof_optional_hdr"]
        return sizeof_opt_hdr

    @property
    def sect_ptr_raw_data(self):
        ptr = self.section_table["ptr_to_raw_data"]
        return ptr

    @property
    def sect_sizeof_raw_data(self):
        rd_size = self.section_table["sizeof_raw_data"]
        return rd_size

    @property
    def sect_virtual_size(self):
        vsize = self.section_table["virtual_size"]
        return vsize
