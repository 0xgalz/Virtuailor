import idc
import idautils
import idaapi
import sys, os
idaapi.require("AddBP")


def get_con2_var_or_num(i_cnt, cur_addr):
    """
    :param i_cnt: the register of the virtual call
    :param cur_addr: the current address in the memory
    :return: "success" string and the address of the vtable's location. if it fails it sends the reason and -1
    """
    save_last_addr = cur_addr
    start_addr = idc.GetFunctionAttr(cur_addr, idc.FUNCATTR_START)
    offset = 0
    cur_addr = idc.PrevHead(cur_addr)

    while cur_addr >= start_addr:
        if idc.GetMnem(cur_addr)[:3] == "mov" and idc.GetOpnd(cur_addr, 0) == i_cnt:
            opnd2 = idc.GetOpnd(cur_addr, 1)
            place = opnd2.find('+')
            register = ''
            offset = ''
            if place != -1: # if the function is not the first in the vtable
                register = opnd2[opnd2.find('[') + 1: place]
                offset = opnd2[place + 1: opnd2.find(']')]
                return register, offset, cur_addr
            else:
                offset = "0"
                register = opnd2[opnd2.find('[') + 1: opnd2.find(']')]
                return register, offset, cur_addr
        cur_addr = idc.PrevHead(cur_addr)
    return "out of the function", "-1", cur_addr

    return '', 0


def get_bp_condition(start_addr, register_vtable, offset):
    condition_file = str(os.path.dirname(os.path.abspath(sys.argv[0]))+'\\BPCond.py')
    with open(condition_file, 'rb') as f1:
        bp_cond_text = f1.read()
    bp_cond_text = bp_cond_text.replace("<<<start_addr>>>", str(start_addr))
    bp_cond_text = bp_cond_text.replace("<<<register_vtable>>>", register_vtable)
    bp_cond_text = bp_cond_text.replace("<<<offset>>>", offset)
    return bp_cond_text



def write_vtable2file(start_addr):
    """
     :param start_addr: The start address of the virtual call
    :return: The break point condition and the break point address
    """
    opnd = get_con2_var_or_num(idc.GetOpnd(start_addr, 0), start_addr)

    reg_vtable = opnd[0]
    offset = opnd[1]
    bp_address = opnd[2]
    set_bp = True
    cond = ""

    try:
        int(offset)
        # If a structure was already assigned to the BP (not by Virtualor), before running the code the code will\
        # assume it was examined by the user, the BP will not be set
        cond =  ""
    except ValueError:
        if offset[:9] == "vtable_0x":
        # A offset structure was set, the old offset will be deleted
            set_bp = False
    finally:
        if set_bp:
            cond = get_bp_condition(start_addr, reg_vtable, offset)
    return cond, bp_address