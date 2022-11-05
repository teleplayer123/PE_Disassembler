from models.pe_file import PEFile


fn = "C:\\PE_Disassembler\\advapi32_copy.dll"

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

for i in range(2, num_sections):
    offset = (i * 40) + sect_offset
    print(f"\nSection Header {i}:")
    sect = p.get_section_table_entry(offset)
    print(sect)