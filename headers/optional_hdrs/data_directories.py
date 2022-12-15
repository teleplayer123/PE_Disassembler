from pe_base.pe_base import PEBase

import ctypes
import struct
from typing import NamedTuple


class DataDirField(ctypes.Structure):

    _fields_ = [
        ("VirtualAddress", ctypes.c_uint32),
        ("Size", ctypes.c_uint32)
    ]

class DataDir(NamedTuple):

    VirtualAddress: str
    Size: str

class DataDirectories(PEBase):

    def get_data_directories(self):
        data_dir = {}
        self.DATA_DIRECTORIES_SIZE = self.DATA_DIRECTORIES.size
        offset = int(self.sig_offset, 16) + self.COFF_HDR_STRUCT.size + self.COFF_FIELD_STRUCT.size + self.WIN_FIELD_STRUCT.size
        data = self.DATA_DIRECTORIES.unpack(self.data[offset:offset+self.DATA_DIRECTORIES.size])
        data_dir["export_table"] = hex(data[0])
        data_dir["export_table_size"] = hex(data[1])
        data_dir["import_table"] = hex(data[2])
        data_dir["import_table_size"] = hex(data[3])
        data_dir["resource_table"] = hex(data[4])
        data_dir["resource_table_size"] = hex(data[5])
        data_dir["exception_table"] = hex(data[6])
        data_dir["exception_table_size"] = hex(data[7])
        data_dir["certificate_table"] = hex(data[8])
        data_dir["certificate_table_size"] = hex(data[9])
        data_dir["base_reloc_table"] = hex(data[10])
        data_dir["base_reloc_table_size"] = hex(data[11])
        data_dir["debug"] = hex(data[12])
        data_dir["debug_size"] = hex(data[13])
        data_dir["arch_data"] = hex(data[14])
        data_dir["arch_data_size"] = hex(data[15])
        data_dir["global_ptr"] = hex(data[16])
        data_dir["global_ptr_size"] = hex(data[17])
        data_dir["tls_table"] = hex(data[18])
        data_dir["tls_table_size"] = hex(data[19])
        data_dir["load_config_table"] = hex(data[20])
        data_dir["load_config_table_size"] = hex(data[21])
        data_dir["bound_import"] = hex(data[22])
        data_dir["bound_import_size"] = hex(data[23])
        data_dir["import_addr_table"] = hex(data[24])
        data_dir["import_addr_table_size"] = hex(data[25])
        data_dir["delay_import_descriptor"] = hex(data[26])
        data_dir["delay_import_descriptor_size"] = hex(data[27])
        data_dir["clr_runtime_header"] = hex(data[28])
        data_dir["clr_runtime_header_size"] = hex(data[29])
        data_dir["reserved"] = hex(data[30])
        data_dir["reserved_size"] = hex(data[31])
        return data_dir

    @property
    def idata_dict(self):
        return self.import_table_dir()

    def convert_entries_to_struct(self):
        struct_dict = {}
        hdr_dict = self.get_data_directories()
        hdr_val_lst = list(hdr_dict.values())
        hdr_idx_lst = list(hdr_dict.keys())
        for i in range(0, len(hdr_val_lst)-1, 2):
            ddf = DataDirField()
            ddf.VirtualAddres = hdr_val_lst[i]
            ddf.Size = hdr_val_lst[i+1]
            struct_dict[str(hdr_idx_lst[i])] = ddf
        return struct_dict

    def convert_entries_to_obj(self):
        obj_dict = {}
        hdr_dict = self.get_data_directories()
        hdr_val_lst = list(hdr_dict.values())
        hdr_idx_lst = list(hdr_dict.keys())
        for i in range(0, len(hdr_val_lst)-1, 2):
            ddf = DataDir(hdr_val_lst[i], hdr_val_lst[i+1])
            obj_dict[str(hdr_idx_lst[i])] = ddf
        return obj_dict

    def export_table_dir(self):
        edata_dict = {}
        edata_struct = struct.Struct("2L2H7L")
        edata_dir = self.convert_entries_to_obj()["export_table"]
        table_start = int(edata_dir.VirtualAddress, 16)
        table_size = int(edata_dir.Size, 16)
        table_end = table_start + table_size
        edata_ptr = table_start
        edata = edata_struct.unpack(self.data[edata_ptr:edata_ptr+edata_struct.size])
        edata_dict["ExportFlags"] = hex(edata[0])
        edata_dict["TimeDateStamp"] = hex(edata[1])
        edata_dict["MajorVersion"] = hex(edata[2])
        edata_dict["MinorVersion"] = hex(edata[3])
        edata_dict["Name_RVA"] = hex(edata[4])
        edata_dict["OrdinalBase"] = hex(edata[5])
        edata_dict["AddressTaableEntries"] = hex(edata[6])
        edata_dict["NumberOfNamePointers"] = hex(edata[7])
        edata_dict["ExportAddressTable_RVA"] = hex(edata[8])
        edata_dict["NamePointer_RVA"] = hex(edata[9])
        edata_dict["OrdinalTable_RVA"] = hex(edata[10])
        return edata_dict

    def _export_addr_table(self, hexstr: str):
        eat_struct = struct.Struct("2L")

    def import_table_dir(self):
        import_table_dict = {}
        idata_struct = struct.Struct("5L")
        idata_dir = self.convert_entries_to_obj()["import_table"]
        table_start = int(idata_dir.VirtualAddress, 16)
        table_size = int(idata_dir.Size, 16)
        table_end = table_start + table_size
        idata_ptr = table_start
        while True:
            if idata_ptr > table_end:
                break
            idata_dict = {}
            data = self.data[idata_ptr:idata_ptr+idata_struct.size]
            idata = idata_struct.unpack(data)
            idata_dict["ImportLookupTable_RVA"] = hex(idata[0])
            idata_dict["TimeDateStamp"] = hex(idata[1])
            idata_dict["ForwarderChain"] = hex(idata[2])
            idata_dict["Name_RVA"] = hex(idata[3])
            idata_dict["ImportAddressTable_RVA"] = hex(idata[4])
            import_table_dict[hex(idata_ptr)] = idata_dict
            idata_ptr += idata_struct.size
            is_ord, ilt_val = self._import_lookup_table(hex(idata[0]))
            print(f"ILT: {ilt_val}")
        return import_table_dict

    def _import_lookup_table(self, hexstr: str):
        arch = self.get_arch_type()
        arch64 = False
        is_ord = False
        ref_data = None
        if arch == "PE32":
            ilt_struct = struct.Struct("L")
            bit_mask = 0x80000000
        elif arch == "PE32+":
            ilt_struct = struct.Struct("Q")
            bit_mask = 0x8000000000000000
            arch64 = True
        ilt_start = int(hexstr, 16)
        ilt_raw_data = self.data[ilt_start:ilt_start+ilt_struct.size]
        if len(ilt_raw_data) == 0:
            return  False ,None
        ilt_data = hex(ilt_struct.unpack(ilt_raw_data)[0])
        ilt_data_int = int(ilt_data, 16)
        flag_bit = ilt_data_int & bit_mask
        if flag_bit == 0:
            is_ord = False
            ref_data = hex(ilt_data_int)
        elif flag_bit == 1:
            is_ord = True
            if arch64 == True:
                ord_data = ilt_data_int >> 48
                ref_data = hex(ord_data)
            else:
                ord_data = ilt_data_int >> 16
                ref_data = hex(ord_data)
        return is_ord, ref_data
