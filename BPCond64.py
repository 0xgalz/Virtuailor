# This is the breakpoint condition code.
# Every value inside the <<< >>> is an argument
# The arguments are:
#    * start_addr -> The virtual call address
#    * register_vtable -> The register who points to the vtable
#    * offset -> The offset of the relevant function from the vtable base pointer

def get_fixed_name_for_object(address, prefix=""):
    """
    :param address: string, the object's address we want to calculate its offset
    :param prefix: string, a prefix for the object name
    :param suffix: string, a suffix for the object name
    :return: returns the new name of the object with calculated offset from the base addr -> "prefix + offset + suffix"
      !! In case the object (in this case function) doesn't starts with "sub_" the returned name will be the old name
    """
    v_func_name = GetFunctionName(int(address))
    print v_func_name, address
    calc_func_name = int(address) - SegStart(int(address))
    if v_func_name[:4] == "sub_":
        v_func_name =  prefix + str(calc_func_name)
    elif v_func_name == "":
        v_func_name =  prefix + str(calc_func_name) #str(v_func_name)[4:] # str(hex(v_func_addr- SegStart(v_func_addr))) the name will be the offset from the beginning of the segment
    return v_func_name

def get_vtable_and_vfunc_addr(is_brac, register_vtable, offset):
    """
    :param is_brac: number, if the call/ assignment is byRef the value is -1
    :param register_vtable: string, the register used in the virtual call
    :param offset: number, the offset of the function in the vtables used in on the bp opcode
    :return: return the addresses of the vtable and the virtual function from the relevant register
    """
    if is_brac == -1: # check it in both start addr and bp if both are [] than anf just than change is_brac
        p_vtable_addr = idc.GetRegValue(register_vtable)
        pv_func_addr = p_vtable_addr + offset
        v_func_addr = idc.read_dbg_qword(pv_func_addr)
        return p_vtable_addr, v_func_addr
    else:
        p_vtable_addr = idc.read_dbg_qword(idc.GetRegValue(register_vtable))
        pv_func_addr = p_vtable_addr + offset
        v_func_addr = idc.read_dbg_qword(pv_func_addr)
        return p_vtable_addr, v_func_addr

def add_comment_to_struct_members(struct_id, vtable_func_offset, start_address):
     # add comment to the vtable struct members
    cur_cmt = idc.GetMemberComment(struct_id, vtable_func_offset, 1)
    if cur_cmt:
        if cur_cmt[:24] != "Was called from address:": ##### change string in the if -> the function call outside of conditions
            succ1 = idc.SetMemberComment(struct_id, vtable_func_offset, "Was called from address: " + start_address, 1)
        else:
            succ1 = idc.SetMemberComment(struct_id, vtable_func_offset, cur_cmt + ", " + start_address, 1)
    else:
        succ1 = idc.SetMemberComment(struct_id, vtable_func_offset, "Was called from address: " + start_address, 1)

    return  succ1

def add_all_functions_to_struct(start_address, struct_id, p_vtable_addr, offset):
    vtable_func_offset = 0
    vtable_func_value = idc.read_dbg_qword(p_vtable_addr)
    # Add all the vtable's functions to the vtable struct
    while vtable_func_value != 0:
        v_func_name = GetFunctionName(vtable_func_value)
        if v_func_name == '':
            vtable_func_value = idc.read_dbg_qword(vtable_func_value)
            v_func_name = GetFunctionName(vtable_func_value)
            if v_func_name == '':
                print "error, address:", start_address
        # Change function name
        v_func_name = get_fixed_name_for_object(int(vtable_func_value), "vfunc_")
        idaapi.set_name(vtable_func_value, v_func_name, idaapi.SN_FORCE)
        # Add to structure
        succ = idc.add_struc_member(struct_id, v_func_name, vtable_func_offset , FF_QWRD, -1, 8)
        if offset == vtable_func_offset:
            add_comment_to_struct_members(struct_id, vtable_func_offset, start_address)
        vtable_func_offset += 8
        vtable_func_value = idc.read_dbg_qword(p_vtable_addr + vtable_func_offset)


def create_vtable_struct(start_address, vtable_name, p_vtable_addr, offset):
    struct_name = vtable_name + "_struct"
    struct_id = add_struc(-1, struct_name, 0)
    if struct_id != idc.BADADDR:
        add_all_functions_to_struct(start_address, struct_id, p_vtable_addr, offset)
        idc.OpStroff(idautils.DecodeInstruction(int(idc.GetRegValue("rip"))), 1, struct_id)
    else:
        struct_id = idc.GetStrucIdByName(struct_name)
        # Checks if the struct exists, in this case the function offset will be added to the struct
        if struct_id != idc.BADADDR:
            idc.OpStroff(idautils.DecodeInstruction(int(idc.GetRegValue("rip"))), 1, struct_id)
        else:
            print "Failed to create struct: " +  struct_name

def do_logic(virtual_call_addr, register_vtable, offset):
    # Checks if the assignment was beRef or byVal
    is_brac_assign = idc.GetOpnd(int(idc.GetRegValue("rip")), 1).find('[')
    # Checks if the assignment was beRef or byVal
    call_addr = int(virtual_call_addr) + SegStart(int(idc.GetRegValue("rip")))
    is_brac_call = idc.GetOpnd(call_addr, 0).find('[')
    is_brac = -1
    if is_brac_assign != -1 and is_brac_call != -1:
        is_brac = 0
    # Get the adresses of the vtable and the virtual function from the relevant register:
    p_vtable_addr, v_func_addr = get_vtable_and_vfunc_addr(is_brac, register_vtable, offset)
    # Change the virtual function name (only in case the function has IDA's default name)
    v_func_name = get_fixed_name_for_object(v_func_addr, "vfunc_")
    idaapi.set_name(v_func_addr, v_func_name, idaapi.SN_FORCE)
    # Change the vtable address name
    vtable_name = get_fixed_name_for_object(p_vtable_addr, "vtable_")
    idaapi.set_name(p_vtable_addr, vtable_name, idaapi.SN_FORCE)
    # create the vtable struct
    create_vtable_struct(virtual_call_addr, vtable_name, p_vtable_addr, offset)

print "bp hit! address:", idc.GetRegValue("rip")
virtual_call_addr = str(<<<start_addr>>>)  # Offset from the beginning of its segment
#print "start_addr:", virtual_call_addr
register_vtable = "<<<register_vtable>>>"
offset = <<<offset>>>
try:
    do_logic(virtual_call_addr, register_vtable, offset)
except:
    print "Error! at address:", hex(idc.GetRegValue("rip"))
a= """
# checks if the call/ assignment was beRef or byVal
is_brac = idc.GetOpnd(here(), 1).find('[')

# Get the adresses of the vtable and the virtual function from the relevant register:
if is_brac == -1:
    p_vtable_addr = idc.GetRegValue("<<<register_vtable>>>")
    pv_func_addr = p_vtable_addr + <<<offset>>>
    v_func_addr = idc.read_dbg_qword(pv_func_addr)
    print "no", v_func_addr

else:
    p_vtable_addr = idc.read_dbg_qword(idc.GetRegValue("<<<register_vtable>>>"))
    pv_func_addr = p_vtable_addr + <<<offset>>>
    v_func_addr = idc.read_dbg_qword(pv_func_addr)
    print "brac!!", v_func_addr

# calculate the offset of the virtual function from the beginning of its section, determine its name
# in case the function name was changed by the user the name will stay the same
v_func_name = GetFunctionName(v_func_addr)
calc_func_name = int(v_func_addr) - SegStart(v_func_addr)
if v_func_name[:4] == "sub_":
    v_func_name =  "vfunc_" + str(calc_func_name) #str(v_func_name)[4:] # str(hex(v_func_addr- SegStart(v_func_addr))) the name will be the offset from the beginning of the segment
    idaapi.set_name(v_func_addr, v_func_name, idaapi.SN_FORCE)


# calculate the offset of the vtable from the beginning of its section, determine its name
calc_struct_name =  int(p_vtable_addr) - SegStart(p_vtable_addr)
vtable_addr_name = "vtable_" + str(calc_struct_name) #  str(p_vtable_addr) +

#change vtable address name
idaapi.set_name(p_vtable_addr, vtable_addr_name, idaapi.SN_FORCE)

# create the vtable struct
struct_name = vtable_addr_name + "_struct"
struct_id = add_struc(-1, struct_name, 0)
if struct_id != idc.BADADDR: # checks if the struct creation succeeded
    # add all the functions of the vtable to the struct
    vtable_func_offset = 0
    vtable_func_value = idc.read_dbg_qword(p_vtable_addr)
    while vtable_func_value != 0:
        v_func_name = GetFunctionName(vtable_func_value)
        if v_func_name == '':
            vtable_func_value = idc.read_dbg_qword(vtable_func_value)
            v_func_name = GetFunctionName(vtable_func_value)
            if v_func_name == '':
                print "error, address:",  str(<<<start_addr>>>)
        calc_func_name = int(vtable_func_value) - SegStart(vtable_func_value)
        if v_func_name[:4] == "sub_":
            v_func_name =  "vfunc_" + str(calc_func_name)#str(v_func_name)[4:] # str(hex(v_func_addr- SegStart(v_func_addr))) the name will be the offset from the beginning of the segment
            idaapi.set_name(vtable_func_value, v_func_name, idaapi.SN_FORCE)
        succ = idc.add_struc_member(struct_id, v_func_name, vtable_func_offset , FF_QWRD, -1, 8)
        vtable_func_offset += 8
        vtable_func_value = idc.read_dbg_qword(p_vtable_addr + vtable_func_offset)

        # add comment to the vtable struct members
        cur_cmt = idc.GetMemberComment(struct_id, vtable_func_offset, 1)
        if cur_cmt:
            if cur_cmt[:24] != "Was called from address:":
                succ1 = idc.SetMemberComment(struct_id, vtable_func_offset, "Was called from address: <<<start_addr>>>", 1) #str(hex(idc.GetRegValue("eip")))
        else:
            succ1 = idc.SetMemberComment(struct_id, vtable_func_offset, "Was called from address: <<<start_addr>>>", 1)
    idc.OpStroff(idautils.DecodeInstruction(int(idc.GetRegValue("rip"))), 1, struct_id)
else:
    struct_id = idc.GetStrucIdByName(struct_name)
    if struct_id != idc.BADADDR: #checks if the struct exists, in this case the function offset will be added to the struct
        idc.OpStroff(idautils.DecodeInstruction(int(idc.GetRegValue("rip"))), 1, struct_id)
    else:
        print "Failed to create struct: " +  struct_name
        #add comments to the assembly
        #last_text = idc.get_cmt(virtual_call_addr, 1)
        #if last_text == None:
            #last_text = ""
        #idc.set_cmt(virtual_call_addr, last_text + "vtable struct is: " +idaapi.get_struc_name(struct_id) + ", function: " + v_func_name, 1)
#except:
    #print "General Error Running the script :O"
1 == 1
"""
#idc.add_cref(0x000000013FA72ABB, 0x000000013FA71177, idc.XREF_USER | idc.fl_F)