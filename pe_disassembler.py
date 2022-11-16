from models.pe_file import PEFile



class PEDisassembler(PEFile):

    @property
    def dos_header(self):
        return self.dos_hdr_obj

    @property
    def coff_header(self):
        return self.coff_hdr_obj

    @property
    def standard_fields(self):
        return self.standard_fields_obj

    @property
    def windows_fields(self):
        return self.win_fields_obj

    @property
    def data_directories(self):
        return self.data_dir_obj

    @property
    def section_table(self):
        return self.section_table_obj

    def _find_rich_hdr(self):
        data = self.data
        sig_offset = int(self.coff_header.get_sig_offset, 16)
        
