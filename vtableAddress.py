from __future__ import print_function
import idc
import idautils
import ida_frame
import ida_struct
import idaapi
import sys, os
idaapi.require("AddBP")

REGISTERS = ['eax', 'ebx', 'ecx', 'edx', 'rax', 'rbx', 'rcx', 'rdx', 'r9', 'r10', 'r8']

def get_processor_architecture():
    info = idaapi.get_inf_structure()
    if info.is_64bit():
        return "64"
    elif info.is_32bit():
        return ""
    else:
        return "Error"


def get_local_var_value_64(loc_var_name):
    frame = ida_frame.get_frame(idc.here())
    loc_var = ida_struct.get_member_by_name(frame, loc_var_name)
    loc_var_start = loc_var.soff
    loc_var_ea = loc_var_start + idc.GetRegValue("RSP")
    loc_var_value = idc.read_dbg_qword(loc_var_ea) # in case the variable is 32bit, just use get_wide_dword() instead
    return loc_var_value

def get_con2_var_or_num(i_cnt, cur_addr):
    """
    :param i_cnt: the register of the virtual call
    :param cur_addr: the current address in the memory
    :return: "success" string and the address of the vtable's location. if it fails it sends the reason and -1
    """
    start_addr = idc.GetFunctionAttr(cur_addr, idc.FUNCATTR_START)
    virt_call_addr = cur_addr
    cur_addr = idc.PrevHead(cur_addr)
    while cur_addr >= start_addr:
        if idc.GetMnem(cur_addr)[:3] == "mov" and idc.GetOpnd(cur_addr, 0) == i_cnt: #TODO lea ?
            opnd2 = idc.GetOpnd(cur_addr, 1)
            place = opnd2.find('+')
            if place != -1: # if the function is not the first in the vtable
                register = opnd2[opnd2.find('[') + 1: place]
                if opnd2.find('*') == -1:
                    offset = opnd2[place + 1: opnd2.find(']')]
                else:
                    offset = "*"
                return register, offset, cur_addr
            else:
                offset = "0"
                if opnd2.find(']') != -1:
                    register = opnd2[opnd2.find('[') + 1: opnd2.find(']')]
                else:
                    register = opnd2
                return register, offset, cur_addr
        elif idc.GetMnem(cur_addr)[:4] == "call":
            intr_func_name = idc.GetOpnd(cur_addr, 0)
            # In case the code has CFG -> ignores the function call before the virtual calls
            if "guard_check_icall_fptr" not in intr_func_name:
                print("Warning! At address 0x%08x: The vtable assignment might be in another function (Maybe %s),\
could not place BP." % (virt_call_addr, intr_func_name))
                cur_addr = start_addr
        cur_addr = idc.PrevHead(cur_addr)
    return "out of the function", "-1", cur_addr

    return '', 0


def get_bp_condition(start_addr, register_vtable, offset):
    arch = get_processor_architecture()
    if arch != "Error":
        file_name = 'BPCond' + arch + '.py'
        condition_file = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), file_name)
        with open(condition_file, 'rb') as f1:
            bp_cond_text = f1.read()
        bp_cond_text = bp_cond_text.replace("<<<start_addr>>>", str(start_addr))
        bp_cond_text = bp_cond_text.replace("<<<register_vtable>>>", register_vtable)
        bp_cond_text = bp_cond_text.replace("<<<offset>>>", offset)
        return bp_cond_text
    return "# Error in BP condition"



def write_vtable2file(start_addr):
    """
     :param start_addr: The start address of the virtual call
    :return: The break point condition and the break point address
    """
    raw_opnd = idc.GetOpnd(start_addr, 0)
    if raw_opnd in REGISTERS:
        reg = raw_opnd
    else:
        for reg in REGISTERS:
            if raw_opnd.find(reg) != -1:
                break
    opnd = get_con2_var_or_num(reg, start_addr)

    reg_vtable = opnd[0]
    offset = opnd[1]
    bp_address = opnd[2]
    set_bp = True
    cond = ""
    # TODO check the get_con2 return variables!!@
    try:
        #TODO If a structure was already assigned to the BP (not by Virtualor), before running the code the code will\
        # assume it was examined by the user, the BP will not be set
        plus_indx = raw_opnd.find('+')
        if plus_indx != -1:
            call_offset = raw_opnd[plus_indx + 1:raw_opnd.find(']')]
            # if the offset is in hex
            if call_offset.find('h') != -1:
                call_offset = int(call_offset[:call_offset.find('h')], 16)
        if offset.find('h') != -1:
            offset = str(int(offset[:offset.find('h')], 16))
    except ValueError:
        # A offset structure was set, the old offset will be deleted
        set_bp = False
    finally:
        if set_bp:
            start_addr = start_addr - idc.SegStart(start_addr)
            if reg_vtable in REGISTERS:
                cond = get_bp_condition(start_addr, reg_vtable, offset)
    return cond, bp_address