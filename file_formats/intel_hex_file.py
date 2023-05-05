import struct
import ctypes
from typing import NamedTuple


class DataRecord(NamedTuple):

    length: ctypes.c_uint8
    load_addr: ctypes.c_uint16
    rec_type: ctypes.c_uint8
    data: list
    checksum: ctypes.c_uint8

    def __repr__(self):
        return f"""
        Length: {hex(self.length)}
        Load Address: {hex(self.load_addr)}
        Type: {hex(self.rec_type)}
        Data: 0x{self.data.decode()}
        Checksum: {hex(self.checksum)}
        """


class IntelHexFile:

    def __init__(self, filename):
        self.data = self._read_hex_file(filename)
        self.records = self.unpack_data()

    def _read_hex_file(self, filename):
        data = []
        with open(filename, "rb") as fh:
            for line in fh:
                line = line.strip(b"\r\n")
                line = line.strip(b":")
                data.append(line)
        return data

    def bin2hex(self, b):
        h = "0x{}".format(b.decode())
        return int(h, 16)

    def unpack_rec(self, rec_entry):

        rec_hdr_struct = struct.Struct("2s4s2s")
        rec_hdr = rec_hdr_struct.unpack(rec_entry[:rec_hdr_struct.size])
        rec_len = self.bin2hex(rec_hdr[0])
        rec_laddr = self.bin2hex(rec_hdr[1])
        rec_type = self.bin2hex(rec_hdr[2])
        rec_data_struct = struct.Struct("{}s".format(rec_len))
        rec_data = rec_data_struct.unpack(rec_entry[8:8+rec_len])[0]
        rec_chksum = self.bin2hex(struct.unpack("2s", rec_entry[-2:])[0])
        rec = DataRecord(rec_len, rec_laddr, rec_type, rec_data, rec_chksum)
        return rec

    def unpack_data(self):
        records = []
        for rec in self.data:
            r = self.unpack_rec(rec)
            records.append(r)
        return records
    
    def __str__(self):
        res = {}
        for i, v in enumerate(self.records):
            res[str(i)] = repr(v)
        return res

    