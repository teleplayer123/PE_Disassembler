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

