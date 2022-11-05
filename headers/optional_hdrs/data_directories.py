from pe_base.pe_base import PEBase

import ctypes


class DataDirField(ctypes.Structure):

    __fields__ = [
        ("VirtualAddress", ctypes.c_uint32),
        ("Size", ctypes.c_uint32)
    ]


class DataDirectories(PEBase):

    def get_data_directories(self):
        data_dir = {}
        self.DATA_DIRECTORIES_SIZE = self.DATA_DIRECTORIES.size
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




