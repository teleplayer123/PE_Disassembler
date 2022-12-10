from pe_base.pe_base import PEBase


class DOSHeader(PEBase):

    def get_dos_hdr(self):
        hdr_dict = {}
        data = self.DOS_HDR_STRUCT.unpack(self.data[0:self.DOS_HDR_STRUCT.size])
        hdr_dict["e_magic"] = hex(data[0])
        hdr_dict["e_cblp"] = hex(data[1])
        hdr_dict["e_cp"] = hex(data[2])
        hdr_dict["e_crlc"] = hex(data[3])
        hdr_dict["e_cparhdr"] = hex(data[4])
        hdr_dict["e_minalloc"] = hex(data[5])
        hdr_dict["e_maxalloc"] = hex(data[6])
        hdr_dict["e_ss"] = hex(data[7])
        hdr_dict["e_sp"] = hex(data[8])
        hdr_dict["e_csum"] = hex(data[9])
        hdr_dict["e_ip"] = hex(data[10])
        hdr_dict["e_cs"] = hex(data[11])
        hdr_dict["e_lfarlc"] = hex(data[12])
        hdr_dict["e_ovno"] = hex(data[13])
        hdr_dict["e_res"] = data[14:18]
        hdr_dict["e_oemid"] = hex(data[18])
        hdr_dict["e_oeminfo"] = hex(data[19])
        hdr_dict["e_res2"] = data[20:30]
        hdr_dict["e_lfanew"] = hex(data[30])
        return hdr_dict

    def parse_rich_hdr(self):
        pass