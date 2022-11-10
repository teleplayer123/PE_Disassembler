import struct


class PEStruct:

    COFF_HDR_STRUCT = struct.Struct("L2H3L2H")
    COFF_FIELD_STRUCT = struct.Struct("H2B6L")
    WIN_FIELD_STRUCT = struct.Struct("3L6H4L2H6L")
    DATA_DIRECTORIES = struct.Struct("32L")
    SECTION_TABLE_STRUCT = struct.Struct("Q6L2HL")


class PEBase(PEStruct):

    def __init__(self, filename: str, byteorder: str="little"):
        self.byteorder = byteorder
        self._filename = filename
        self.data = self.read_file()

    def read_file(self):
        data = None
        with open(self._filename, "rb") as fh:
            data = fh.read()
        return data