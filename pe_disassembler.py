from models.pe_file import PEFile

from pprint import pformat, pprint
import sys

class PEDisassembler:

    def __init__(self, filename: str, byteorder: str="little"):
        self.pe = PEFile(filename, byteorder=byteorder)

    @property
    def print_coff_hdr(self):
        print("\n\nCOFF Header")
        print("-"*16)
        pprint(self.pe.coff_hdr, sort_dicts=False)

    @property
    def print_standard_hdr(self):
        print("\n\nStandard Header")
        print("-"*16)
        pprint(self.pe.standard_fields, sort_dicts=False)

    @property
    def print_win_hdr(self):
        print("\n\nWindows Header")
        print("-"*16)
        pprint(self.pe.win_fields, sort_dicts=False)

    @property
    def print_data_dirs(self):
        print("\n\nData Directories")
        print("-"*16)
        pprint(self.pe.data_directories, sort_dicts=False)

    @property
    def print_data_dir_objects(self):
        print("\n\nData Directory Objects")
        print("-"*16)
        print(self.pe.get_data_dirs, sort_dicts=False)

    @property
    def print_section_hdrs(self):
        print("\n\nSection Headers")
        print("-"*16)
        print(f"Number of Sections: {self.pe.num_of_sections}")
        print("Section Header 1:")
        pprint(self.pe.section_table, sort_dicts=False)
        num_sections = self.pe.num_of_sections
        sect_offset = self.pe.sect_offset
        last_offset = 0
        for i in range(1, num_sections):
            offset = (i * 40) + sect_offset
            print(f"\nSection Header {i+1}:")
            sect = self.pe.get_section_table_entry(offset)
            pprint(sect, sort_dicts=False)
            last_offset = offset
        return last_offset

    @property
    def get_section_dict(self):
        num_sections = self.pe.num_of_sections
        sect_offset = self.pe.sect_offset
        sec_dict = self.pe.section_table_obj.get_sections(num_sections, sect_offset)
        return sec_dict

    @property
    def print_section_dict(self):
        sec_dict = self.get_section_dict()
        print("\n\nSection Dictionary")
        print("-"*16)
        print(pformat(sec_dict, sort_dicts=False))

    def section_hexdump(self, offset: int):
        hres = self.pe.dump_section(self.pe.data, offset)
        return hres

    def print_section_hexdump(self, offset: int):
        hres = self.section_hexdump(offset)
        print("\n\nSection HexDump Offset: {}".format(hex(offset)))
        print("-"*16)
        print(hres)

    def print_hexdump(self, offset: int, size: int, hdr_str: str="Data HexDump"):
        hres = self.pe.dump_section(self.pe.data, offset=offset, sec_size=size)
        print(f"\n\n{hdr_str}")
        print("-"*16)
        print(hres)
    
    @property
    def print_dos_hdr_dump(self):
        sig_offset = int(self.pe.coff_hdr_obj.get_sig_offset, 16)
        offset = 0
        print("\n\nDOS Header Data")
        print("-"*16)
        rhdr = self.pe.dump_section(self.pe.data, offset, sig_offset)
        print(rhdr)

    @property
    def print_dos_hdr(self):
        print("\n\nDOS Header")
        print("-"*16)
        pprint(self.pe.dos_hdr, sort_dicts=False)   
        print("Sig Offset {}".format(self.pe.coff_hdr_obj.sig_offset))

    @property
    def print_rich_hdr(self):
        print("\n\nRich Header Offset")
        print("-"*16)
        print(self.pe.rich_hdr_offset)
        print("\nRich Header Checksum")
        print("-"*16)
        print(self.pe.rich_hdr_checksum)

    def print_section_data(self, sec_num: int):
        print("\n\nSection Data")
        print("-"*16)
        print(self.pe.get_section_data(sec_num)["hexdump"])

    @property
    def print_section_names(self):
        names = self.pe.section_names
        print("\n\nSection Names")
        print("-"*16)
        for name in names:
            print(f"\t{name}")

    @property
    def print_import_table(self):
        try:
            print("\n\nImport Table")
            print("-"*16)
            pprint(self.pe.get_import_table(), sort_dicts=False)
        except Exception:
            print("\nNO IMPORT TABLE")

    @property
    def print_export_table(self):
        try:
            print("\n\nExport Table")
            print("-"*16)
            pprint(self.pe.get_export_table(), sort_dicts=False)
        except Exception:
            print("\nNO EXPORT TABLE")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: py {sys.argv[0]} <pefile_path>")
        sys.exit()
    fn = sys.argv[1]
    p = PEDisassembler(fn)
    p.print_dos_hdr
    p.print_rich_hdr
    p.print_coff_hdr
    p.print_standard_hdr
    p.print_win_hdr
    p.print_data_dirs
    p.print_section_hdrs
    p.print_section_names
    #p.print_hexdump(0xae9000, 104834, hdr_str="INITKDBG")

if __name__ == "__main__":
    main()