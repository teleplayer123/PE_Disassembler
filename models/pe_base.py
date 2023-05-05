import struct


class PEStruct:

    DOS_HDR_STRUCT = struct.Struct("30HL")
    COFF_HDR_STRUCT = struct.Struct("L2H3L2H")
    MAGIC_STRUCT = struct.Struct("H")
    COFF_FIELD_STRUCT = struct.Struct("H2B6L")
    COFF64_FIELD_STRUCT = struct.Struct("H2B5L")
    WIN64_FIELD_STRUCT = struct.Struct("Q2L6H4L2H4Q2L")
    WIN_FIELD_STRUCT = struct.Struct("3L6H4L2H6L")
    DATA_DIRECTORIES = struct.Struct("32L")
    SECTION_TABLE_STRUCT = struct.Struct("Q6L2HL")


class PEBase(PEStruct):

    def __init__(self, filename: str, byteorder: str="little"):
        self.byteorder = byteorder
        self._filename = filename
        self.data = self.read_file()

    @property
    def dos_hdr(self):
        dos_hdr = struct.unpack("H", self.data[0:2])[0]
        return hex(dos_hdr)

    @property
    def sig_offset(self):
        sig_offset = struct.unpack("L", self.data[int(0x3c):int(0x3c)+4])[0]
        return hex(sig_offset)

    def read_file(self):
        data = None
        with open(self._filename, "rb") as fh:
            data = fh.read()
        return data

    def hexstr2val(self, hexstr: str, val_dict: dict):
        res = None
        n = int(hexstr, 16)
        for k, v in val_dict.items():
            if n == v:
                res = k
                break
        return res

    def hexstr2arr(self, hexstr: str, val_dict: dict, nsize: int=4):
        vals = []
        n = int(hexstr, 16)
        for i in range(1, nsize+1):
            mask = int("0x{}".format("f"*i), 16)
            j = (i * 4) - 4
            x = ((n & mask) >> j) << j
            for k, v in val_dict.items():
                if x == v:
                    vals.append(k)
                    break
        return vals

    def get_arch_type(self):
        offset = int(self.sig_offset, 16) + self.COFF_HDR_STRUCT.size
        arch_type = self.MAGIC_STRUCT.unpack(self.data[offset:offset+self.MAGIC_STRUCT.size])
        res = self.magic_number(hex(arch_type[0]))
        return res

    def magic_number(self, hexstr: str):
        magic_nums = {
            "PE32": 0x10b,
            "PE32+": 0x20b
        }
        res = self.hexstr2val(hexstr, magic_nums)
        return res

    def decode_hexstr(self, hexstr: str):
        res = ""
        hexstr = hexstr[2:]
        for i in range(0, len(hexstr), 2):
            c = "0x{}{}".format(hexstr[i], hexstr[i+1])
            c = chr(int(c, 16))
            res = str(c) + res
        return res