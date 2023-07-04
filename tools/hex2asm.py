from capstone import *
import sys

from file_formats.intel_hex_file import IntelHexFile



def main():
    #fname = str(sys.argv[1])
    fname = r"C:\tools\firmware\pca10040-20230426-v1.20.0.hex"
    disasm = Cs(CS_ARCH_X86, CS_MODE_64)

    #with open(fname, "r") as fh:
        #code = fh.read()
    xfile = IntelHexFile(fname)
    code = xfile.records
    #res = disasm.disasm(code, offset=0x0000)
    #print([i for i in res])
    print(code)

