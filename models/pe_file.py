from headers.optional_hdrs.data_directories import DataDirectories, DataDir
from headers.optional_hdrs.standard_fields import StandardFields
from headers.optional_hdrs.windows_fields import WindowsFields
from headers.dos_hdr import DOSHeader
from headers.coff_hdr import COFFHeader
from headers.section_table import SectionTable
from tools.hexdump import xdump

import struct


class PEFile:

    def __init__(self, filename: str, byteorder: str="little"):
        self.data = self.read_file(filename)
        self.dos_hdr_obj = DOSHeader(filename)
        self.dos_hdr = self.dos_hdr_obj.get_dos_hdr()
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
    def coff_ptr_to_sym_table(self):
        return self.coff_hdr["ptr_to_symbol_table"]

    @property
    def num_of_sections(self):
        num_of_sections = self.coff_hdr["number_of_sections"]
        return num_of_sections

    @property
    def sizeof_opt_hdr(self):
        sizeof_opt_hdr = int(self.coff_hdr["sizeof_optional_hdr"], 16)
        return sizeof_opt_hdr

    @property
    def sect_virtual_size(self):
        vsize = self.section_table["virtual_size"]
        return vsize

    @property
    def rich_hdr_offset(self):
        hdr_offset = None
        for i in range(len(self.data)):
            dword = self.data[i:i+4]
            if dword == b"Rich":
                hdr_offset = (dword, i)
                break
        return hex(hdr_offset[1]), hdr_offset[0]

    @property
    def rich_hdr_checksum(self):
        offset = int(self.rich_hdr_offset[0], 16) + 4
        cs_unpacked = struct.unpack("L", self.data[offset:offset+4])
        checksum = hex(cs_unpacked[0])
        return checksum

    @property
    def get_data_dirs(self):
        data_dirs = self.data_dir_obj.convert_entries_to_obj()
        return data_dirs

    @property
    def section_names(self):
        names = self.section_table_obj.SECTION_NAMES
        return names

    def data_dirs_aligned(self):
        aligned_data_dirs = {}
        data_dirs = self.get_data_dirs
        align_n = int(self.win_fields["file_alignment"], 16)
        for name in data_dirs.keys():
            aligned_size = None
            dd = data_dirs[name]
            dd_size = int(dd.Size, 16)
            if dd_size % align_n == 0:
                aligned_size = dd_size
            else:
                aligned_size = dd_size + (align_n - (dd_size % align_n))
            aligned_data_dirs[name] = DataDir(dd.VirtualAddress, hex(aligned_size))
        return aligned_data_dirs

    def decode_bin2text(self, hexstr: str):
        res = ""
        hexstr = hexstr[2:]
        if len(hexstr) % 2 != 0:
            hexstr = "0"+hexstr
        for i in range(0, len(hexstr), 2):
            c = "0x{}{}".format(hexstr[i], hexstr[i+1])
            c = chr(int(c, 16))
            res = c + res
        return res

    def get_import_table(self):
        if not ".idata" in self.section_names:
            return None
        import_table = self.data_dir_obj.import_table_dir()
        return import_table

    def get_export_table(self):
        if not ".edata" in self.section_names:
            return None
        export_table = self.data_dir_obj.export_table_dir()
        return export_table

    def get_section_data(self, sec_num: int):
        sec_data = {}
        sec_dict = self.section_table_obj.get_sections(self.num_of_sections, self.sect_offset)
        sec = sec_dict[str(sec_num)]
        data_ptr = int(sec["ptr_to_raw_data"], 16)
        data_size = int(sec["sizeof_raw_data"], 16)
        data = self.data[data_ptr: data_ptr+data_size]
        sec_data["raw_data"] = data
        sec_data["hexdump"] = xdump(data)
        return sec_data 

    def get_coff_sym_table(self):
        sym_table_dict = {}
        sym_table_struct = struct.Struct("QL2H2B")
        table_ptr = int(self.coff_ptr_to_sym_table, 16)
        raw_data = self.data[table_ptr:table_ptr+sym_table_struct.size]
        table_data = sym_table_struct.unpack(raw_data)
        sym_table_dict["Name"] = self.decode_bin2text(hex(table_data[0]))
        sym_table_dict["Value"] = hex(table_data[1])
        sym_table_dict["SectiionNumber"] = hex(table_data[2])
        sym_table_dict["Type"] = hex(table_data[3])
        sym_table_dict["StorageClass"] = hex(table_data[4])
        sym_table_dict["NumberOfAuxSymbols"] = hex(table_data[5])
        return sym_table_dict