from file_formats.pe_file import PEFile
import sys

def print_headers():
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
    last_offset = 0
    for i in range(1, num_sections):
        offset = (i * 40) + sect_offset
        print(f"\nSection Header {i+1}:")
        sect = p.get_section_table_entry(offset)
        print(sect)
        last_offset = offset

    print("\n\nSection Dictionary")
    print("-"*16)
    print(p.section_table_obj.get_sections(num_sections, sect_offset))

    hres = p.dump_section(p.data, last_offset)
    print("\n\nLast Section HexDump")
    print("-"*16)
    print(hres)
    print(f"\nLast Offset: {last_offset+40}")
    print(f"\nLength of Data: {len(p.data)}")


    sig_offset = int(p.coff_hdr_obj.get_sig_offset, 16)
    offset = 0
    print("\n\nDOS Header Data")
    print("-"*16)
    rhdr = p.dump_section(p.data, offset, sig_offset)
    print(rhdr)

    print("\n\nDOS Header")
    print("-"*16)
    print(p.dos_hdr)   
    print("Sig Offset")
    print(p.coff_hdr_obj.sig_offset)

    print("\n\nRich Header Offset")
    print("-"*16)
    print(p.rich_hdr_offset)

    print("\nRich Header Checksum")
    print("-"*16)
    print(p.rich_hdr_checksum)

    #print("\n\nSection Data")
    #print("-"*16)
    #print(p.get_section_data(3)["hexdump"])


if __name__ == "__main__":
    print_headers()