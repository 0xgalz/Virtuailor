from __future__ import print_function
import idc
import idautils
import idaapi

idaapi.require("AddBP")
idaapi.require("vtableAddress")
idaapi.require("GUI")

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
        elif idc.GetMnem(cur_addr) == 'call' or idc.GetMnem(cur_addr) == 'BLR':
            if True in [idc.GetOpnd(cur_addr, 0).find(reg) != -1 for reg in REGISTERS]:  # idc.GetOpnd(cur_addr, 0) in REGISTERS:
                cond, bp_address = vtableAddress.write_vtable2file(cur_addr)
                if cond != '':
                    bp_vtable = AddBP.add(bp_address, cond)
        cur_addr = idc.NextHead(cur_addr)


def set_values(start, end):
    start = start
    end = end
    return start, end


if __name__ == '__main__':
    start_addr_range = idc.MinEA()  # You can change the virtual calls address range
    end_addr_range = idc.MaxEA()
    oldTo = idaapi.set_script_timeout(0)
    # Initializes the GUI: Deletes the 0x in the beginning and the L at the end:
    gui = GUI.VirtuailorBasicGUI(set_values, {'start': hex(start_addr_range)[2:-1], 'end': hex(end_addr_range)[2:-1]})
    gui.exec_()
    if gui.start_line.text != "banana":
        add_bp_to_virtual_calls(int(gui.start_line.text(),16), int(gui.stop_line.text(), 16))

