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
        self.num_of_sections = self.coff_hdr["number_of_sections"]
        sizeof_opt_hdr = self.coff_hdr["sizeof_optional_hdr"]
        self.standard_fields_obj = StandardFields(filename, byteorder=byteorder)
        self.standard_fields = self.standard_fields_obj.get_standard_fields()
        self.win_fields_obj = WindowsFields(filename, byteorder=byteorder)
        self.win_fields = self.win_fields_obj.get_win_fields()
        self.data_dir_hdr = DataDirectories(filename, byteorder=byteorder)
        self.data_directories = self.data_dir_hdr.get_data_directories()
        sig_offset = int(self.coff_hdr_obj.get_sig_offset, 16)
        self.sect_offset = sig_offset + self.coff_hdr_obj.size + sizeof_opt_hdr
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

    def dump_last_section(self, data, offset: int):
        try:
            chunk = data[offset:]
            return xdump(chunk)
        except IndexError:
            print("Data not available at offset {}".format(offset))
            return

