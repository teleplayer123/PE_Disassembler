from pe_base.pe_base import PEBase


class StandardFields(PEBase):

    def get_standard_fields(self):
        coff_fields = {}
        pe64 = False
        offset = int(self.sig_offset, 16) + self.COFF_HDR_STRUCT.size
        magic_data = self.MAGIC_STRUCT.unpack(self.data[offset:offset+self.MAGIC_STRUCT.size])
        coff_fields["magic"] = f"{self.magic_number(hex(magic_data[0]))}: {hex(magic_data[0])}"
        if self.magic_number(hex(magic_data[0])) == "PE32+":
            COFF_FIELD_STRUCT = self.COFF64_FIELD_STRUCT
            pe64 = True
        else:
            COFF_FIELD_STRUCT = self.COFF_FIELD_STRUCT
        self.COFF_FIELD_STRUCT_SIZE = COFF_FIELD_STRUCT.size
        coff_data = COFF_FIELD_STRUCT.unpack(self.data[offset:offset+COFF_FIELD_STRUCT.size])
        coff_fields["maj_linker_ver"] = hex(coff_data[1])
        coff_fields["min_linker_ver"] = hex(coff_data[2])
        coff_fields["code_size"] = hex(coff_data[3])
        coff_fields["init_data_size"] = hex(coff_data[4])
        coff_fields["uninit_data_size"] = hex(coff_data[5])
        coff_fields["entry_point_addr"] = hex(coff_data[6])
        coff_fields["code_base_addr"] = hex(coff_data[7])
        if pe64 == False:
            coff_fields["data_base_addr"] = hex(coff_data[8])
        return coff_fields



