import idc
import idautils
import idaapi
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
    return "out of the function", -1, cur_addr

    return '', 0


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
            cond += """
#addr = """ + str(int(bp_address)) + """ #idc.here()
virtual_call_addr = """ + str(start_addr) + """ #idc.NextHead(idc.here())

# Get the adresses of the  vtable and the virtual function from the relevant register:
p_vtable_addr = idc.GetRegValue(\"""" + reg_vtable + """\")
pv_func_addr = idc.GetRegValue(\"""" + reg_vtable + """\") + """ + offset + """
v_func_addr = get_wide_dword(pv_func_addr)

# calculate the offset of the virtual function from the beginning of its section, determine its name
v_func_name = GetFunctionName(v_func_addr) # in case the function name was changed by the user the name will stay the same
if v_func_name[:4] == "sub_":
    v_func_name =  "vfunc_" + "__" + str(v_func_name) # str(hex(v_func_addr- SegStart(v_func_addr))) the name will be the offset from the beginning of the segment
print v_func_name

# create the vtable struct and calculate the offset of the vtable from the beginning of its section, determine its name
#calc_struct_name =  int(p_vtable_addr) - SegStart(p_vtable_addr)
struct_name = "vtable_" + str(p_vtable_addr) #str(calc_struct_name)

#change vtable address name
#idaapi.set_name(p_vtable_addr, struct_name, idaapi.SN_FORCE)

struct_id = add_struc(-1, struct_name, 0)
print struct_id, struct_name
if struct_id != 4294967295: # checks if the struct creation succeeded
    # add structure members and change the offset structure in the assembly
    idc.add_struc_member(struct_id, v_func_name, """ + offset + """ , FF_DWRD, -1, 4)
    idc.SetMemberComment(struct_id, """ + offset + """ , "Was called form address:" + str(hex(idc.GetRegValue("eip"))) , 1)
    print "%%%%structure_id%%%%", struct_id #idc.GetRegValue("eip")
    idc.OpStroff(idautils.DecodeInstruction(int(idc.GetRegValue("eip"))), 1, struct_id)

    #add comments to the assembly
    last_text = idc.get_cmt(virtual_call_addr, 1)
    if last_text == None:
        last_text = ""
    idc.set_cmt(virtual_call_addr, last_text + "vtable struct is: " +idaapi.get_struc_name(struct_id) + ", function: " + v_func_name, 1)
1 == 1
        """
    return cond, bp_address