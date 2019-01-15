from __future__ import print_function
import idc
import idautils
import idaapi

idaapi.require("AddBP")
idaapi.require("vtableAddress")

from vtableAddress import REGISTERS

def get_all_functions():
    for func in idautils.Functions():
        print(hex(func), idc.GetFunctionName(func))


def get_xref_code_to_func(func_addr):
    a = idautils.XrefsTo(func_addr, 1)
    addr = {}
    for xref in a:
        frm = xref.frm  # ea in func
        start = idc.GetFunctionAttr(frm, idc.FUNCATTR_START)  # to_xref func addr
        func_name = idc.GetFunctionName(start)  # to_xref func name
        addr[func_name] = [xref.iscode, start]
    return addr


def add_bp_to_virtual_calls(cur_addr, end):
    while cur_addr < end:
        if cur_addr == idc.BADADDR:
            break
        elif idc.GetMnem(cur_addr) == 'call':
            if True in [idc.GetOpnd(cur_addr, 0).find(reg) != -1 for reg in
                        REGISTERS]:  # idc.GetOpnd(cur_addr, 0) in REGISTERS:
                cond, bp_address = vtableAddress.write_vtable2file(cur_addr)
                if cond != '':
                    bp_vtable = AddBP.add(bp_address, cond)
        cur_addr = idc.NextHead(cur_addr)


if __name__ == '__main__':
    start_addr_range = idc.MinEA()  # You can change the virtual calls address range
    end_addr_range = idc.MaxEA()
    add_bp_to_virtual_calls(start_addr_range, end_addr_range)
