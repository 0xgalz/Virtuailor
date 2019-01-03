# This is the breakpoint condition code.
# Every value inside the <<< >>> is an argument
# The arguments are:
#    * start_addr -> The virtual call address
#    * register_vtable -> The register who points to the vtable
#    * offset -> The offset of the relevant function from the vtable base pointer
#import idaapi

virtual_call_addr = str(<<<start_addr>>>)  #idc.NextHead(idc.here())

# check if we want the register or the regidter value
is_brac = idc.GetOpnd(here(), 1).find('[')

# Get the adresses of the  vtable and the virtual function from the relevant register:
if is_brac == -1:
    p_vtable_addr = idc.GetRegValue("<<<register_vtable>>>")
    pv_func_addr = p_vtable_addr + <<<offset>>>
    v_func_addr = get_wide_dword(pv_func_addr)
    print "no", v_func_addr

else:
    p_vtable_addr = get_wide_dword(idc.GetRegValue("<<<register_vtable>>>"))
    pv_func_addr = p_vtable_addr + <<<offset>>>
    v_func_addr = get_wide_dword(pv_func_addr)
    print "brac!!", v_func_addr

# Get the adresses of the  vtable and the virtual function from the relevant register:
#p_vtable_addr = idc.GetRegValue("<<<register_vtable>>>")
#pv_func_addr = idc.GetRegValue("<<<register_vtable>>>") + <<<offset>>>
#v_func_addr = get_wide_dword(pv_func_addr)

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
    vtable_func_value = get_wide_dword(p_vtable_addr)
    while vtable_func_value != 0:
        v_func_name = GetFunctionName(vtable_func_value)
        calc_func_name = int(vtable_func_value) - SegStart(vtable_func_value)
        if v_func_name[:4] == "sub_":
            v_func_name =  "vfunc_" + str(calc_func_name)#str(v_func_name)[4:] # str(hex(v_func_addr- SegStart(v_func_addr))) the name will be the offset from the beginning of the segment
            idaapi.set_name(vtable_func_value, v_func_name, idaapi.SN_FORCE)
        succ = idc.add_struc_member(struct_id, v_func_name, vtable_func_offset , FF_DWRD, -1, 4)
        vtable_func_offset += 4
        vtable_func_value = get_wide_dword(p_vtable_addr + vtable_func_offset)

        #succ1 = idc.SetMemberComment(struct_id, vtable_func_offset, "Was called form address: <<<start_addr>>>", 1) #str(hex(idc.GetRegValue("eip")))
    idc.OpStroff(idautils.DecodeInstruction(int(idc.GetRegValue("eip"))), 1, struct_id)
else:
    struct_id = idc.GetStrucIdByName(struct_name)
    if struct_id != idc.BADADDR: #checks if the struct exists, in this case the function offset will be added to the struct
        idc.OpStroff(idautils.DecodeInstruction(int(idc.GetRegValue("eip"))), 1, struct_id)
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