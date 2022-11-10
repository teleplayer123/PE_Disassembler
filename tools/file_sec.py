from collections import defaultdict
import os
import sys
import win32security
import ntsecuritycon
import pywintypes
import winerror


class FileCheckSec:

    def __init__(self, filename: str):
        self.fname = filename

    def owner_info(self):
        res = None
        try:
            sd = win32security.GetFileSecurity(self.fname, win32security.OWNER_SECURITY_INFORMATION)
            sid = sd.GetSecurityDescriptorOwner()
            res = "{}".format(win32security.LookupAccountSid(None, sid))
        except pywintypes.error as err:
            if err.winerror != winerror.ERROR_NONE_MAPPED:
                res = "Error: {}".format(str(err))
            else:
                res = "Owner info not available"
        return res

    def group_info(self):
        res = None
        try:
            sd = win32security.GetFileSecurity(self.fname, win32security.GROUP_SECURITY_INFORMATION)
            sid = sd.GetSecurityDescriptorGroup()
            res = "{}".format(win32security.LookupAccountSid(None, sid))
        except pywintypes.error as err:
            if err.winerror != winerror.ERROR_NONE_MAPPED:
                res = "Error: {}".format(str(err))
            else:
                res = "Group info not available"
        return res

    def discretionary_acl_file(self):
        ace_dict = defaultdict(dict)
        ace_types = [
            "ACCESS_ALLOWED_ACE_TYPE",
            "ACCESS_DENIED_ACE_TYPE",
            "SYSTEM_AUDIT_ACE_TYPE",
            "SYSTEM_ALARM_ACE_TYPE"
            ]
        ace_flags = [
            "OBJECT_INHERIT_ACE",
            "CONTAINER_INHERIT_ACE",
            "NO_PROPAGATE_INHERIT_ACE",
            "INHERIT_ONLY_ACE",
            "SUCCESSFUL_ACCESS_ACE_FLAG",
            "FAILED_ACCESS_ACE_FLAG"          
        ]
        file_perms = [
            "DELETE",
            "READ_CONTROL",
            "WRITE_DAC",
            "WRITE_OWNER",
            "SYNCHRONIZE",
            "FILE_GENERIC_READ",
            "FILE_GENERIC_WRITE",
            "FILE_GENERIC_EXECUTE",
            "FILE_DELETE_CHILD"           
        ]

        sd = win32security.GetFileSecurity(self.fname, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl == None:
            ace_dict = "No Discretionary ACL"
        else:
            for ace_num in range(dacl.GetAceCount()):
                ace = dacl.GetAce(ace_num)
                ace_dict[f"ACE{ace_num}"]["ace_type"] = hex(ace[0][0])
                ace_dict[f"ACE{ace_num}"]["ace_types"] = [e for e in ace_types if getattr(ntsecuritycon, e) == ace[0][0]]
                ace_dict[f"ACE{ace_num}"]["ace_flag"] = hex(ace[0][1])
                ace_dict[f"ACE{ace_num}"]["ace_flags"] = [e for e in ace_flags if getattr(ntsecuritycon, e) & ace[0][1] == getattr(ntsecuritycon, e)]
                ace_dict[f"ACE{ace_num}"]["ace_mask"] = hex(ace[1])
                
                calc_mask = 0
                ace_dict[f"ACE{ace_num}"]["file_permissions"] = []
                for e in file_perms:
                    if getattr(ntsecuritycon, e) & ace[1] == getattr(ntsecuritycon, e):
                        calc_mask = calc_mask | getattr(ntsecuritycon, e)
                        ace_dict[f"ACE{ace_num}"]["file_permissions"].append(e)
                ace_dict[f"ACE{ace_num}"]["calc_mask"] = hex(calc_mask)
                ace_dict[f"ACE{ace_num}"]["sid"] = "{}".format(win32security.LookupAccountSid(None, ace[2]))
        return ace_dict



