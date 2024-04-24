<<<<<<< HEAD
from capstone import *
import sys


def main(fname):
    #fname = str(sys.argv[1])
    disasm = Cs(CS_ARCH_X86, CS_MODE_64)
    isa_list = []
    with open(fname, "rb") as fh:
        code = fh.read()
    size = len(code)
    for i in range(size):
        res = disasm.disasm(code, offset=i)
        isa_list.append([i for i in res])
    print(isa_list)

=======
from capstone import *
import sys

from file_formats.intel_hex_file import IntelHexFile



def main(fname):
    #fname = str(sys.argv[1])
    disasm = Cs(CS_ARCH_X86, CS_MODE_64)

    #with open(fname, "r") as fh:
        #code = fh.read()
    xfile = IntelHexFile(fname)
    code = xfile.records
    #res = disasm.disasm(code, offset=0x0000)
    #print([i for i in res])
    print(code)

>>>>>>> 636177df35748b3d4ae6837c72e5066eb18641f9
