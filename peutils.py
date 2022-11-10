from models.pe_file import PEFile
from tools.file_sec import FileCheckSec

from pprint import pformat
import sys


def show_file_sec():
    if len(sys.argv) < 2:
        print(f"Usage: py {sys.argv[0]} <file_path>")
        sys.exit()
    fn = sys.argv[1]
    f = FileCheckSec(fn)

    o = f.owner_info()
    print("Owner Info:\n")
    print("\t{}".format(o))

    g = f.group_info()
    print("Group Info:\n")
    print("\t{}".format(g))

    d = f.discretionary_acl_file()
    print("Discretionary ACL:\n")
    print("\t{}".format(pformat(d)))


def show_pefile_hdrs():
    if len(sys.argv) < 2:
        print(f"Usage: py {sys.argv[0]} <pefile_path>")
        sys.exit()
    fn = sys.argv[1]

    p = PEFile(fn)
    print("COFF Header")
    print("-"*16)
    print(p.coff_hdr)

    print("\n\n")
    print("Standard Header")
    print("-"*16)
    print(p.standard_fields)

    print("\n\n")
    print("Windows Header")
    print("-"*16)
    print(p.win_fields)

    print("\n\n")
    print("Data Directories")
    print("-"*16)
    print(p.data_directories)

    print("\n\n")
    print("Section Headers")
    print("-"*16)
    print(f"Number of Sections: {p.num_of_sections}")
    print("Section Header 1:")
    print(p.section_table)

    num_sections = p.num_of_sections
    sect_offset = p.sect_offset

    for i in range(1, num_sections):
        offset = (i * 40) + sect_offset
        print(f"\nSection Header {i+1}:")
        sect = p.get_section_table_entry(offset)
        print(sect)