from headers.optional_hdrs.data_directories import DataDirectories
from headers.optional_hdrs.standard_fields import StandardFields
from headers.optional_hdrs.windows_fields import WindowsFields
from headers.coff_hdr import COFFHeader
from headers.section_table import SectionTable


class PEFile:

    def __init__(self, filename: str, byteorder: str="little"):
        _coff_hdr = COFFHeader(filename, byteorder=byteorder)
        self.coff_hdr = _coff_hdr.get_coff_hdr()
        self.num_of_sections = self.coff_hdr["number_of_sections"]
        sizeof_opt_hdr = self.coff_hdr["sizeof_optional_hdr"]
        _standard_fields = StandardFields(filename, byteorder=byteorder)
        self.standard_fields = _standard_fields.get_standard_fields()
        _win_fields = WindowsFields(filename, byteorder=byteorder)
        self.win_fields = _win_fields.get_win_fields()
        _data_dir_hdr = DataDirectories(filename, byteorder=byteorder)
        self.data_directories = _data_dir_hdr.get_data_directories()
        sig_offset = int(_coff_hdr.get_sig_offset, 16)
        self.sect_offset = sig_offset + _coff_hdr.size + sizeof_opt_hdr
        self._section_table = SectionTable(filename, byteorder=byteorder)
        self.section_table = self._section_table.get_section_table(self.sect_offset)


    def get_section_table_entry(self, offset: int):
        entry = self._section_table.get_section_table(offset)
        return entry

    def seek_hdr_offset(self, hdr_class, offset: int):
        pass


