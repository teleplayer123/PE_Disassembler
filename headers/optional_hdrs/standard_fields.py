from pe_base.pe_base import PEBase


class StandardFields(PEBase):

    def get_standard_fields(self):
        coff_fields = {}
        offset = int(self.sig_offset, 16) + self.COFF_HDR_STRUCT.size
        self.COFF_FIELD_STRUCT_SIZE = self.COFF_FIELD_STRUCT.size
        coff_data = self.COFF_FIELD_STRUCT.unpack(self.data[offset:offset+self.COFF_FIELD_STRUCT.size])
        coff_fields["magic"] = f"{self.magic_number(hex(coff_data[0]))}: {hex(coff_data[0])}"
        coff_fields["maj_linker_ver"] = hex(coff_data[1])
        coff_fields["min_linker_ver"] = hex(coff_data[2])
        coff_fields["code_size"] = hex(coff_data[3])
        coff_fields["init_data_size"] = hex(coff_data[4])
        coff_fields["uninit_data_size"] = hex(coff_data[5])
        coff_fields["entry_point_addr"] = hex(coff_data[6])
        coff_fields["code_base_addr"] = hex(coff_data[7])
        coff_fields["data_base_addr"] = hex(coff_data[8])
        return coff_fields



