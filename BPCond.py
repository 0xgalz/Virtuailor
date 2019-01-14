# This is the breakpoint condition code.
# Every value inside the <<< >>> is an argument that will be replaced by "vtableAddress.py"
# The arguments are:
#    * start_addr -> The offset of the virtual call from the beginning of its segment
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
    calc_func_name = int(address) - SegStart(int(address))
    if v_func_name[:4] == "sub_":
        v_func_name =  prefix + str(calc_func_name)
    elif v_func_name == "":
        v_func_name =  prefix + str(calc_func_name) # The name will be the offset from the beginning of the segment
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
        v_func_addr = get_wide_dword(pv_func_addr)
        return p_vtable_addr, v_func_addr
    else:
        p_vtable_addr = get_wide_dword(idc.GetRegValue(register_vtable))
        pv_func_addr = p_vtable_addr + offset
        v_func_addr = get_wide_dword(pv_func_addr)
        return p_vtable_addr, v_func_addr

def add_comment_to_struct_members(struct_id, vtable_func_offset, start_address):
     # add comment to the vtable struct members
    cur_cmt = idc.GetMemberComment(struct_id, vtable_func_offset, 1)
    new_cmt = ""
    if cur_cmt:
        if cur_cmt[:23] != "Was called from offset:":
            new_cmt = cur_cmt
        else:
            new_cmt = cur_cmt + ", " + start_address
    else:
        new_cmt = "Was called from offset: " + start_address
    succ1 = idc.SetMemberComment(struct_id, vtable_func_offset, new_cmt, 1)
    return  succ1

def add_all_functions_to_struct(start_address, struct_id, p_vtable_addr, offset):
    vtable_func_offset = 0
    vtable_func_value = get_wide_dword(p_vtable_addr)
    # Add all the vtable's functions to the vtable struct
    while vtable_func_value != 0:
        v_func_name = GetFunctionName(vtable_func_value)
        if v_func_name == '':
            vtable_func_value = get_wide_dword(vtable_func_value)
            v_func_name = GetFunctionName(vtable_func_value)
            if v_func_name == '':
                print "Error in adding functions to struct, at BP address::0x%08x" % start_address
        # Change function name
        v_func_name = get_fixed_name_for_object(int(vtable_func_value), "vfunc_")
        idaapi.set_name(vtable_func_value, v_func_name, idaapi.SN_FORCE)
        # Add to structure
        succ = idc.add_struc_member(struct_id, v_func_name, vtable_func_offset , FF_DWRD, -1, 4)
        if offset == vtable_func_offset:
            add_comment_to_struct_members(struct_id, vtable_func_offset, start_address)
        vtable_func_offset += 4
        vtable_func_value = get_wide_dword(p_vtable_addr + vtable_func_offset)


def create_vtable_struct(start_address, vtable_name, p_vtable_addr, offset):
    struct_name = vtable_name + "_struct"
    struct_id = add_struc(-1, struct_name, 0)
    if struct_id != idc.BADADDR:
        add_all_functions_to_struct(start_address, struct_id, p_vtable_addr, offset)
        idc.OpStroff(idautils.DecodeInstruction(int(idc.GetRegValue("eip"))), 1, struct_id)
    else:
        struct_id = idc.GetStrucIdByName(struct_name)
        # Checks if the struct exists, in this case the function offset will be added to the struct
        if struct_id != idc.BADADDR:
            idc.OpStroff(idautils.DecodeInstruction(int(idc.GetRegValue("eip"))), 1, struct_id)
        else:
            print "Failed to create struct: " +  struct_name

def do_logic(virtual_call_addr, register_vtable, offset):
    # Checks if the assignment was beRef or byVal
    is_brac_assign = idc.GetOpnd(int(idc.GetRegValue("eip")), 1).find('[')
    # Checks if the assignment was beRef or byVal
    call_addr = int(virtual_call_addr) + SegStart(int(idc.GetRegValue("eip")))
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
    # Add xref of the virtual call
    idc.add_cref(call_addr, v_func_addr, idc.XREF_USER | idc.fl_F)
    # create the vtable struct
    create_vtable_struct(virtual_call_addr, vtable_name, p_vtable_addr, offset)

virtual_call_addr = str(<<<start_addr>>>)  # Offset from the beginning of its segment
#print "start_addr:", virtual_call_addr
register_vtable = "<<<register_vtable>>>"
offset = <<<offset>>>
try:
    do_logic(virtual_call_addr, register_vtable, offset)
except:
    print "Error! at BP address: 0x%08x", idc.GetRegValue("eip")

#idc.add_cref(0x000000013FA72ABB, 0x000000013FA71177, idc.XREF_USER | idc.fl_F)
