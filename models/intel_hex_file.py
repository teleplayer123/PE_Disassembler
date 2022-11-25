import struct
import ctypes


class DataRecord(ctypes.Structure):

    _fields_ = [
        ("length", ctypes.c_uint8),
        ("load_addr", ctypes.c_uint16),
        ("type", ctypes.c_uint8),
        ("data", ctypes.POINTER(ctypes.c_ubyte)),
        ("checksum", ctypes.c_uint8)
    ]


class IntelHexFile:

    def __init__(self, filename):
        self.data = self._read_hex_file(filename)
        self.records = []

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
        rec = DataRecord()
        rec_hdr_struct = struct.Struct("2s4s2s")
        rec_hdr = rec_hdr_struct.unpack(rec_entry[:rec_hdr_struct.size])
        rec_len = self.bin2hex(rec_hdr[0])
        rec_laddr = self.bin2hex(rec_hdr[1])
        rec_type = self.bin2hex(rec_hdr[2])
        rec_data_struct = struct.Struct("{}B".format(rec_len))
        rec_data = rec_data_struct.unpack(rec_entry[8:8+rec_len])
        rec_chksum = self.bin2hex(struct.unpack("2s", rec_entry[-2:])[0])
        rec_data = (ctypes.c_ubyte * rec_len)(*rec_data)
        rec.length = rec_len
        rec.load_addr = rec_laddr
        rec.type = rec_type
        rec.data = rec_data
        rec.checksum = rec_chksum
        return rec

    

    