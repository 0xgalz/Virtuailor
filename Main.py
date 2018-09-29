import idc
import idautils
import idaapi


idaapi.require("AddBP")
idaapi.require("vtableAddress")

REGISTERS = ['eax', 'ebx', 'ecx', 'edx']

def get_all_functions():
    for func in idautils.Functions():
        print hex(func), idc.GetFunctionName(func)


def get_xref_code_to_func(func_addr):
    a = idautils.XrefsTo(func_addr, 1)
    addr = {}
    for xref in a:
        frm = xref.frm  # ea in func
        start = idc.GetFunctionAttr(frm, idc.FUNCATTR_START)  # to_xref func addr
        func_name = idc.GetFunctionName(start)  # to_xref func name
        addr[func_name] = [xref.iscode, start]
    return addr


def add_bp_to_virtual_calls():
    cur_addr = MinEA()
    end = MaxEA()
    all_addrs = []
    while cur_addr < end:
        if cur_addr == idc.BADADDR:
            break
        elif idc.GetMnem(cur_addr) == 'call':
            print "Its a call! ", idc.GetOpnd(cur_addr, 0)
            if idc.GetOpnd(cur_addr, 0) in REGISTERS:
                print cur_addr, "enter write BP!"
                cond, bp_address = vtableAddress.write_vtable2file(cur_addr)
                if cond != '':
                    bp_vtable = AddBP.add(bp_address, cond)
        cur_addr = idc.NextHead(cur_addr)


add_bp_to_virtual_calls()
